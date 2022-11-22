// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <linux/idxd.h>

#include "common.h"
#include "cpu.h"
#include "dsa.h"
#include "util.h"

static void
init_buffers_common(char *b, uint64_t blen, uint64_t stride, int n, uint8_t val)
{
	int i;

	for (i = 0; i < n; i++) {
		memset(b, val, blen);
		b += stride;
	}
}

static void
prep_delta_src2(char *p, int pdiff, uint64_t blen)
{
	struct {
		int start;
		int incr;
	} si[6] = { {0, 0}, {0, 10}, {0, 5}, {0, 3}, {2, 5}, {0, 2}};
	int o;

	if (pdiff == 0) {
		*p = TEST_CHAR + 1;
		return;
	}

	/*
	 * for a % diff of 10, the 0th uint64_t is different then you
	 * increment by 10 so thats where you get the {start, incr} in si[],
	 * for pdiff < 6 we  use the si[] to distribute the deltas, if not we
	 * decide the deltas are dense, for dense deltas, deltas are created
	 * in contiguous uint64_ts within the block of 10.
	 */

	if (pdiff < 6)  {
		for (o = 0; o < blen/8; o += si[pdiff].incr) {
			p[o * 8] = TEST_CHAR + 1;
			if (si[pdiff].start && o + si[pdiff].start < blen/8)
				p[(o + si[pdiff].start) * 8] = TEST_CHAR + 1;
		}

		return;
	}

	for (o = 0; o < blen; o += 10) {
		int j;

		for (j = 0; j < pdiff; j++) {
			if (o + j < blen/8)
				p[(o + j) * 8] = TEST_CHAR + 1;
		}
	}
}

static void
init_bv(struct tcfg_cpu *tcpu, char **b, uint8_t *v)
{
	char *ib[3] = { NULL };
	uint8_t iv[3] = { 0 };

	struct tcfg *tcfg;
	char *src, *src1, *src2;
	struct delta_rec *dptr;
	uint32_t nb_delta_rec;
	int i;

	tcfg = tcpu->tcfg;
	src = tcpu->src;
	src1 = tcpu->src1;
	src2 = tcpu->src2;

	tcfg = tcpu->tcfg;

	memcpy(b, ib, ARRAY_SIZE(ib) * sizeof(ib[0]));
	memcpy(v, iv, ARRAY_SIZE(iv) * sizeof(iv[0]));

	switch (tcfg->op) {

	case DSA_OPCODE_DIF_INS:
	case DSA_OPCODE_MEMMOVE:
		b[0] = src;
		v[0] = tcpu->cpu_num + 1;
		break;

	case DSA_OPCODE_COMPVAL:
		b[0] = src;
		v[0] = TEST_CHAR;
		break;

	case DSA_OPCODE_COMPARE:
		b[0] = src1;
		b[1] = src2;
		v[0] = TEST_CHAR;
		v[1] = TEST_CHAR;
		break;

	case DSA_OPCODE_CR_DELTA:
		for (i = 0; i < tcfg->nb_bufs; i++)
			prep_delta_src2(tcpu->src2 + i * tcfg->bstride,
					tcfg->delta/10, tcfg->blen);
		break;

	case DSA_OPCODE_AP_DELTA:
		src1 = calloc(tcfg->blen, sizeof(char));
		src2 = calloc(tcfg->blen, sizeof(char));
		prep_delta_src2(src2, tcfg->delta/10, tcfg->blen);
		cr_delta(src1, src2, tcpu->delta, tcfg->blen);
		nb_delta_rec = tcfg->delta_rec_size/sizeof(*dptr);
		dptr = tcpu->delta + nb_delta_rec;

		for (i = 1; i < tcfg->nb_bufs; i++) {
			memmove(dptr, tcpu->delta, tcfg->delta_rec_size);
			dptr += nb_delta_rec;
		}

		free(src1);
		free(src2);
		break;

	case DSA_OPCODE_CRCGEN:
		b[0] = src;
		v[0] = tcpu->cpu_num + 1;
		break;

	case DSA_OPCODE_COPY_CRC:
		b[0] = src;
		v[0] = TEST_CHAR;
		break;

	}
}

void
init_buffers(struct tcfg_cpu *tcpu)
{
	char *b[3];
	uint8_t v[3];
	unsigned int i;
	struct tcfg *tcfg = tcpu->tcfg;

	if (!tcfg->verify && !tcfg->op_info->init_req)
		return;

	init_bv(tcpu, b, v);

	for (i = 0; i < ARRAY_SIZE(b); i++) {
		if (b[i])
			init_buffers_common(b[i], tcfg->blen_arr[i], tcfg->bstride_arr[i],
				tcfg->nb_bufs, v[i]);
	}
}

static int
invld_range(void *base, uint64_t len)
{
	int rc;

	rc = mprotect(base, len, PROT_READ);
	if (rc) {
		rc = errno;
		ERR("mprotect1 error: %s", strerror(errno));
		return -rc;
	}

	rc = mprotect(base, len, PROT_READ | PROT_WRITE);
	if (rc) {
		rc = errno;
		ERR("mprotect2 error: %s", strerror(errno));
		return -rc;
	}

	return 0;
}

int
iotlb_invd(struct tcfg *tcfg)
{
	int i;
	int rc;

	for (i = 0; i < tcfg->nb_numa_node; i++) {
		void *p = tcfg->numa_mem[i].base_addr;
		uint64_t sz = page_align_sz(tcfg, tcfg->numa_mem[i].sz);

		INFO("Invalidating range %p 0x%016lx\n", p, sz);

		rc = invld_range(p, sz);
		if (rc)
			return rc;
	}
	return 0;
}

static void
access_place_bufs(char *buf, uint32_t n, uint64_t sz, uint32_t stride,
		int a, int p)
{
	volatile char *u;
	uint32_t i, j;

	if (!buf)
		return;

	if (a == OP_NONE && p == OP_NONE)
		return;

	for (i = 0; i < n; i++) {
		for (j = 0; j < sz/64; j++) {
			u = &buf[j * 64];

			__builtin_ia32_clflush(&buf[j * 64]);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
			switch (a) {

			case OP_NONE:
				break;

			case OP_WRITE:
				*u = *u;
				break;

			case OP_READ:
				*u;
				break;

			default:
				ERR("unrecognized access op %d\n", a);
				break;
			}

			switch (p) {

			case OP_NONE:
			case OP_FETCH:
				break;

			case OP_DEMOTE:
				*u = *u;
				cldemote(u);
				break;

			case OP_FLUSH:
				__builtin_ia32_clflush(&buf[j * 64]);
				break;

			default:
				ERR("unrecognized placement %d\n", p);
				break;
			}
#pragma GCC diagnostic pop
		}

		buf += stride;
	}

	__builtin_ia32_mfence();
}

void
do_cache_ops(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg;
	int i;

	INFO_CPU(tcpu, "Cache ops\n");

	tcfg = tcpu->tcfg;

	for (i = 0; i < ARRAY_SIZE(tcpu->b); i++)
		access_place_bufs(tcpu->b[i], tcfg->nb_bufs, tcfg->blen_arr[i],
			tcfg->bstride_arr[i], tcfg->access_op[i], tcfg->place_op[i]);

	__builtin_ia32_mfence();
}

static int
verify_memmove(struct tcfg_cpu *tcpu, char *src, char *dst, int n)
{
	uint32_t len;
	int i;
	struct tcfg *tcfg;

	tcfg = tcpu->tcfg;
	len = tcfg->blen;

	for (i = 0; i < n; i++) {
		if (memcmp(src, dst, len)) {
			ERR("%d: memory comparison failed src(%p) dst(%p) len(%d)\n",
				i, src, dst, len);
			dump_desc(&tcpu->desc[i]);
			tcpu->err = 1;
			return 1;
		}

		src += tcfg->bstride;
		dst += tcfg->bstride;
	}

	return 0;
}

static int
verify_crc(struct tcfg_cpu *tcpu, char *dst, int block_idx)
{
	struct t10_pi_tuple *actual, *expected;

	actual = (struct t10_pi_tuple *)(dst + tcpu->tcfg->bl_len);
	expected = tcpu->dif_tag + block_idx;

	return (actual->guard_tag != expected->guard_tag);
}

static int
verify_dif(struct tcfg_cpu *tcpu, char *dst, char *src, int n)
{
	struct tcfg *tcfg;
	uint32_t j;
	int i;
	uint32_t nb_blocks;
	char *bsrc, *bdst;
	int src_adj, dst_adj;

	tcfg = tcpu->tcfg;
	nb_blocks = tcfg->blen/tcfg->bl_len;

	src_adj = (tcfg->blen_arr[0] - tcfg->blen)/nb_blocks;
	dst_adj = (tcfg->blen_arr[1] - tcfg->blen)/nb_blocks;

	for (i = 0; i < n; i++) {

		bsrc = src + i * tcfg->bstride_arr[0];
		bdst = dst + i * tcfg->bstride_arr[1];

		for (j = 0; j < nb_blocks; j++) {
			if (memcmp(bsrc, bdst, tcfg->bl_len)) {
				ERR("memcmp failed\n");
				return 1;
			}

			if ((tcfg->op == DSA_OPCODE_DIF_INS ||
				tcfg->op == DSA_OPCODE_DIF_UPDT)
				 && verify_crc(tcpu, bdst, j)) {
				ERR("crc comparision failed\n");
				return 1;
			}

			bsrc += tcfg->bl_len + src_adj;
			bdst += tcfg->bl_len + dst_adj;
		}
	}

	return 0;
}

static int
verify_dif_strip(struct tcfg_cpu *tcpu, char *dst, char *src, int n)
{
	return verify_dif(tcpu, dst, src, n);
}

static int
verify_dif_ins(struct tcfg_cpu *tcpu, char *dst, char *src, int n)
{
	return verify_dif(tcpu, dst, src, n);
}

static int
verify_dif_updt(struct tcfg_cpu *tcpu, char *dst, char *src, int n)
{
	return verify_dif(tcpu, dst, src, n);
}

static int
verify_memfill(struct tcfg_cpu *tcpu, char *dst, int n)
{
	int len;
	int i, j;
	struct tcfg *tcfg;
	uint64_t *d8;
	uint8_t *f1, *d1;

	tcfg = tcpu->tcfg;
	len = tcfg->blen;

	for (i = 0; i < n; i++) {
		d8 = (uint64_t *)dst;
		for (j = 0; j < len/8; j++) {
			if (d8[j] != tcfg->fill) {
				ERR("memory comparison failed fill(%lx) dst(%lx)\n",
				tcfg->fill, d8[j]);
				ERR("buffer address %p\n", &d8[j]);
				tcpu->err = 1;
				return 1;
			}
		}

		d1 = (uint8_t *)&d8[len/8];
		f1 = (uint8_t *)&tcfg->fill;

		for (j = 0; j < len % 8; j++) {
			if (d1[j] != f1[j]) {
				ERR("memory comparison failed fill(%x) dst(%x)\n",
				f1[j], d1[j]);
				ERR("buffer address %p\n", &d1[j]);
				tcpu->err = 1;
				return 1;
			}
		}
		dst += tcfg->bstride;
	}

	return 0;
}

static int
verify_buf_dc(struct tcfg_cpu *tcpu, char *dst1, char *dst2, char *src,
	int n)
{
	struct tcfg *tcfg;

	tcfg = tcpu->tcfg;

	if (!tcfg->verify)
		return 0;

	tcpu->err = verify_memmove(tcpu, dst1, src, n);
	if (tcpu->err)
		return tcpu->err;

	tcpu->err = verify_memmove(tcpu, dst2, src, n);
	return tcpu->err;
}

static int
verify_ap_delta(struct tcfg_cpu *tcpu, char *dst, int n)
{
	struct tcfg *tcfg;
	struct delta_rec *dptr;
	int nb_delta_rec;
	int i, j;
	uint64_t *p8;

	tcfg = tcpu->tcfg;
	nb_delta_rec = tcfg->delta_rec_size/sizeof(*dptr);
	dptr = tcpu->delta;

	for (i = 0; i < n; i++) {

		p8 = (uint64_t *)dst;
		for (j = 0; j < nb_delta_rec; j++) {
			int o = dptr[j].off;

			if (p8[o] != dptr[j].val) {
				ERR("ap delta failed buffer %d offset %d\n",
					i, j);
				tcpu->err = 1;
				return 1;
			}
		}

		dst += tcfg->bstride;
	}

	return 0;
}

static int
verify_buf_sc(struct tcfg_cpu *tcpu, char *src, char *dst, int n)
{
	struct tcfg *tcfg;

	tcfg = tcpu->tcfg;

	if (!tcfg->verify)
		return 0;

	switch (tcfg->op) {

	case DSA_OPCODE_MEMMOVE:
	case DSA_OPCODE_COPY_CRC:
		tcpu->err = verify_memmove(tcpu, src, dst, n);
		break;

	case DSA_OPCODE_MEMFILL:
		tcpu->err = verify_memfill(tcpu, dst, n);
		break;

	case DSA_OPCODE_AP_DELTA:
		tcpu->err = verify_ap_delta(tcpu, dst, n);
		break;

	case DSA_OPCODE_DIF_STRP:
		tcpu->err = verify_dif_strip(tcpu, dst, src,
						n);
		break;

	case DSA_OPCODE_DIF_INS:
		tcpu->err = verify_dif_ins(tcpu, dst, src, n);
		break;

	case DSA_OPCODE_DIF_UPDT:
		tcpu->err = verify_dif_updt(tcpu, dst, src,
						n);
		break;
	}

	return tcpu->err;
}

int
verify_buf(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;

	if (!tcfg->verify)
		return 0;

	return  tcfg->op == DSA_OPCODE_DUALCAST ?
		verify_buf_dc(tcpu, tcpu->dst1, tcpu->dst2,
				tcpu->src, tcfg->nb_bufs) :
		verify_buf_sc(tcpu, tcpu->src, tcpu->dst,
				tcfg->nb_bufs);
}

struct tcfg_disp {
	const char *name_str;
	size_t off;
	const char **val_str;
	int size;
	int base;
};

static char *
gen_format_str(struct tcfg_disp *t)
{
	char format[80];
	static const char *const size[256] = { [0] = NULL, [1] = "hh", [2 ... 7] = NULL, [8] = "l" };
	static const char *const base[256][17] = { [1][10] = "d", [1][16] = "x", [4][10] = "d",
				[4][16] = "x", [8][10] = "d", [8][16] = "x" };
	const char *c;
	char *f;

	snprintf(format, sizeof(format), "%s",  "%-20s %10");
	f = malloc(80);
	if (!f)
		return NULL;
	memmove(f, format, strlen(format) + 1);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wstringop-overflow="
	c = size[t->size];
	if (c)
		memmove(f + strlen(f), c, strlen(c) + 1);
	c = base[t->size][t->base];
	if (c)
		memmove(f + strlen(f), c, strlen(c) + 1);

	memmove(f + strlen(f), "\n", strlen("\n") + 1);
#pragma GCC diagnostic pop

	return f;
}

static void
print_numa_info(struct tcfg *tcfg)
{
	int i, j;

	fprintf(stdout, "Memory affinity\n");
	for (i = 0; i < tcfg->nb_numa_node; i++) {
		if (!tcfg->numa_nb_cpu[i])
			continue;
		fprintf(stdout, "CPUs in node %d:\t\t", i);
		for (j = 0; j < tcfg->op_info->nb_buf; j++)
			fprintf(stdout, "%d ", tcfg->numa_node[i][j]);
		printf("\n");
	}
}

static void
print_offsets(struct tcfg *tcfg)
{
	int i;

	fprintf(stdout, "Buffer Offsets \t\t");
	for (i = 0; i < tcfg->op_info->nb_buf; i++)
		fprintf(stdout, "%hd ", tcfg->buf_off[i]);
	printf("\n");
}

void
print_tcfg(struct tcfg *tcfg)
{
	static const char *place_str[] = { NULL, "None", "L1L2", "LLC", "Memory" };
	static const char *access_str[] = { NULL, "None", "Read", "Write" };
	int i;
	struct tcfg_disp *t;

#define MAKE_DISP_INT(x, b)\
	{.name_str = #x, .off = offsetof(struct tcfg, x), .size = sizeof(tcfg->x), .base = (b) }
#define MAKE_DISP_10(x) MAKE_DISP_INT(x, 10)

#define MAKE_DISP_STR(x, str)\
	{.name_str = #x, .off = offsetof(struct tcfg, x), .val_str = str }

	static struct tcfg_disp tcfg_disp[] = {
		MAKE_DISP_10(blen),	MAKE_DISP_10(bstride),
		MAKE_DISP_10(bstride),	MAKE_DISP_10(nb_bufs),
		MAKE_DISP_10(pg_size),	MAKE_DISP_10(wq_type),
		MAKE_DISP_10(batch_sz),
		MAKE_DISP_10(iter),
		MAKE_DISP_10(nb_cpus),
		MAKE_DISP_10(var_mmio), MAKE_DISP_10(dma),
		MAKE_DISP_10(verify), MAKE_DISP_INT(misc_flags, 16),
		MAKE_DISP_STR(access_op[0], access_str), MAKE_DISP_STR(access_op[1], access_str),
		MAKE_DISP_STR(access_op[2], access_str),
		MAKE_DISP_STR(place_op[0], place_str), MAKE_DISP_STR(place_op[1], place_str),
		MAKE_DISP_STR(place_op[2], place_str),
		MAKE_DISP_INT(flags_cmask, 16), MAKE_DISP_INT(flags_smask, 16),
		MAKE_DISP_10(flags_nth_desc),
		MAKE_DISP_10(nb_numa_node),
		MAKE_DISP_10(cpu_desc_work)
	};

	t = tcfg_disp;

	for (i = 0; i < ARRAY_SIZE(tcfg_disp); i++) {
		char *f;

		if (t->val_str) {
			int j = *(uint32_t *)((char *)tcfg + t->off);

			if (j != -1)
				fprintf(stdout, "%s%20s\n", t->name_str, t->val_str[j]);
			t++;
			continue;
		}

		f = gen_format_str(t);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		fprintf(stdout, f, t->name_str, *(uint64_t *)((char *)tcfg + t->off));
#pragma GCC diagnostic pop
		free(f);
		t++;
	}

	print_numa_info(tcfg);
	print_offsets(tcfg);
}

static void
iter_count_stat(uint64_t *stat, uint64_t *prev, uint64_t *curr)
{
	*stat += *curr - *prev;
	*prev = *curr;
}

static void
count_stat(struct iter_stat *is, struct tcfg_cpu *tcpu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(is->stat); i++)
		iter_count_stat(&is->stat[i], &tcpu->prev_stat.stat[i],
				&tcpu->curr_stat.stat[i]);
}

static void
iter_count(struct tcfg *tcfg, struct iter_stat *iter_stat)
{
	unsigned int i;
	struct iter_stat is = {};

	for (i = 0; i < tcfg->nb_cpus; i++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

		count_stat(&is, tcpu);
	}

	*iter_stat = is;
}

static void
calc_cycles(struct tcfg *tcfg)
{
	uint32_t i;
	uint64_t min, max;
	uint64_t cycles;
	bool use_tval_secs;

	cycles = 0;
	max = min = 0;

	/*
	 * convert tval_secs to cycles if conditions below are true
	 * in cpu mode, when nb_cpus = 1, tval_secs cannot be converted to cycles since
	 * it would include the time spent in data placement (llc v/s dram)
	 */
	use_tval_secs = !!tcfg->tval_secs;
	use_tval_secs &= !(!tcfg->dma && tcfg->nb_cpus == 1);

	if (use_tval_secs) {
		tcfg->bw_cycles = tcfg->cycles = tcfg->cycles_per_sec * tcfg->tval_secs;
		return;
	}

	for (i = 0; i < tcfg->nb_cpus; i++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

		if (i == 0)
			min = max = tcpu->tstart;

		if (min > tcpu->tstart)
			min = tcpu->tstart;
		if (max < tcpu->tend)
			max = tcpu->tend;

		cycles += tcpu->cycles;
	}

	tcfg->cycles = cycles / tcfg->nb_cpus;
	tcfg->bw_cycles = tcfg->dma ? max - min : tcfg->cycles;
}

static void
calc_cpu(struct tcfg *tcfg)
{
	if (tcfg->dma) {
		uint64_t retry_cycles = (tcfg->retry * tcfg->cycles_per_sec)/tcfg->retries_per_sec;
		uint64_t ca;

		/*
		 * cycles available (ca) = retry cycles + mwait cycles
		 * cpu util % = 100 * (1 - ca/total cycles)
		 */
		ca = retry_cycles + tcfg->mwait_cycles;
		tcfg->cpu_util = 100.0 * (1 - (1.0 * ca)/tcfg->cycles);
	} else
		tcfg->cpu_util = 100;
}

static void
calc_work_sub_rate(struct tcfg *tcfg)
{
	uint64_t usecs = (tcfg->cycles * 1000 * 1000)/tcfg->cycles_per_sec;

	tcfg->kops_rate = (tcfg->iter * 1000) / usecs;
}

static void
calc_ops_rate(struct tcfg *tcfg)
{
	long nb_ops;
	uint64_t usecs = (tcfg->bw_cycles * 1000 * 1000)/tcfg->cycles_per_sec;

	if (!usecs)
		return;

	/* kops = (ops/sec) * (1/1000) = ops/msec = (ops * 1000)/usec */
	nb_ops = tcfg->iter * tcfg->nb_cpus * tcfg->nb_bufs;

	if (tcfg->op == DSA_OPCODE_CFLUSH)
		nb_ops = (nb_ops * tcfg->blen)/64;
	else if (tcfg->op == DSA_OPCODE_CR_DELTA)
		nb_ops = (nb_ops * tcfg->blen)/4096;

	tcfg->kops_rate = (nb_ops * 1000)/usecs;
}

static void
calc_bw(struct tcfg *tcfg)
{
	float secs;

	secs = (float)tcfg->bw_cycles/tcfg->cycles_per_sec;
	tcfg->bw = tcfg->iter * (data_size_per_iter(tcfg)/secs)/1000000000;
}

static void
calc_lat(struct tcfg *tcfg)
{
	tcfg->latency = 1.0 * tcfg->cycles / tcfg->iter;

	if (!(tcfg->misc_flags & (TEST_M64|TEST_DB | TEST_M64MEM | TEST_ENQ | TEST_ENQMEM)))
		tcfg->latency /= tcfg->nb_desc;
}

static void
calc_drain_latency(struct tcfg *tcfg)
{
	int i;
	struct tcfg_cpu *tcpu;
	uint64_t drain_lat = 0;
	int cpu_completed = 0;

	for (i = 0; i < tcfg->nb_cpus; i++) {
		tcpu = &tcfg->tcpu[i];
		if (!tcpu->nb_drain_completed)
			continue;
		drain_lat += tcpu->drain_total_cycles / tcpu->nb_drain_completed;
		cpu_completed++;
	}

	if (cpu_completed)
		drain_lat /= cpu_completed;

	tcfg->drain_lat = drain_lat;
}

static void
update_iter(struct tcfg *tcfg, uint32_t nb_iter)
{
	/* use tcfg->iter */
	if (!tcfg->tval_secs)
		return;

	/*
	 * if cpu && nb_cpus ==1, cycles needed for data placement need
	 * to be excluded, tcfg->cycles is updated every iter with the cycles
	 * consumed by the op and current bw = cycles / current iteration count
	 *
	 * the calulation below generates the current iteration count
	 */
	if (!tcfg->dma && tcfg->nb_cpus == 1) {
		if (tcfg->iter == -1)
			tcfg->iter = 0;
		tcfg->iter += nb_iter;
		return;
	}

	tcfg->iter = nb_iter / tcfg->nb_cpus;
}

void
do_results(struct tcfg *tcfg)
{
	struct iter_stat is;

	iter_count(tcfg, &is);

	calc_cycles(tcfg);

	update_iter(tcfg, is.iter);

	tcfg->retry = is.retry / tcfg->nb_cpus;
	tcfg->mwait_cycles = is.mwait_cycles / tcfg->nb_cpus;

	calc_cpu(tcfg);
	calc_bw(tcfg);
	calc_lat(tcfg);
	calc_drain_latency(tcfg);
	is_work_rate_sub_test(tcfg) ?
		calc_work_sub_rate(tcfg) : calc_ops_rate(tcfg);
}

struct thread_data {
	pthread_mutex_t mutex;
	pthread_cond_t cv;
	pthread_mutexattr_t mutex_attr;
	pthread_condattr_t cv_attr;
	uint32_t barrier_cnt;
	bool err;
};

int
test_barrier_init(struct tcfg *tcfg)
{
	struct thread_data *td;

	td = mmap(NULL, sizeof(*td), PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (td == MAP_FAILED) {
		ERR("Failed to allocate thread data\n");
		return -ENOMEM;
	}

	pthread_mutexattr_init(&td->mutex_attr);
	pthread_mutexattr_setpshared(&td->mutex_attr,
				tcfg->proc ? PTHREAD_PROCESS_SHARED :
				PTHREAD_PROCESS_PRIVATE);
	pthread_condattr_init(&td->cv_attr);
	pthread_condattr_setpshared(&td->cv_attr, !!tcfg->proc);
	pthread_mutex_init(&td->mutex, &td->mutex_attr);
	pthread_cond_init(&td->cv, &td->cv_attr);

	tcfg->td = td;

	return 0;
}

int
test_barrier(struct tcfg *tcfg, bool err)
{
	__builtin_ia32_sfence();

	if (err)
		tcfg->td->err = err;

	if (tcfg->nb_cpus == 1)
		return err;

	pthread_mutex_lock(&tcfg->td->mutex);
	tcfg->td->barrier_cnt++;
	if (tcfg->td->barrier_cnt < tcfg->nb_cpus)
		pthread_cond_wait(&tcfg->td->cv, &tcfg->td->mutex);
	else {
		tcfg->td->barrier_cnt = 0;
		pthread_cond_broadcast(&tcfg->td->cv);
	}
	pthread_mutex_unlock(&tcfg->td->mutex);

	return tcfg->td->err;
}

void
test_barrier_free(struct tcfg *tcfg)
{
	struct thread_data *td = tcfg->td;

	if (!td)
		return;

	pthread_mutexattr_destroy(&td->mutex_attr);
	pthread_condattr_destroy(&td->cv_attr);
	pthread_mutex_destroy(&td->mutex);
	pthread_cond_destroy(&td->cv);

	munmap(td, align(sizeof(*td), 4096));
}
