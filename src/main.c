// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/wait.h>

#include "common.h"
#include "dsa.h"
#include "device.h"
#include "prep.h"
#include "init.h"
#include "options.h"
#include "cpu.h"
#include "util.h"
#include "log.h"

#define CACHE_LINE_SZ	64
#define INF_LOOP_SHOW_STATS 1000000

struct log_ctx log_ctx;

static inline void
work_sub_rate_test(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	struct dsa_hw_desc *desc;
	struct dsa_completion_record *comp;
	uint32_t it;
	uint64_t cyc;
	char *wq_ptr;
	uint32_t max_iter = tcfg->iter;
	char *mdest;

	printf("%s using nop\n", __func__);

	desc = tcpu->desc;
	comp = tcpu->comp;
	comp->status = 0;
	__builtin_ia32_sfence();

	if (tcfg->misc_flags & TEST_M64MEM) {
		mdest = aligned_alloc(0x1000, 0x1000);
		if (!mdest) {
			tcpu->err = -ENOMEM;
			return;
		}
	} else
		mdest = NULL;

	cyc = rdtsc();

	if (tcfg->misc_flags & (TEST_M64|TEST_M64MEM)) {
		char *dest = tcpu->wq;
		char *orig_dest = dest;

		if (mdest)
			dest = mdest;

		printf("Measure MOVDIR64B throughput\n");
		for (it = 0; it < max_iter; it++) {
			movdir64b(desc, dest);
			if (tcfg->var_mmio) {
				dest = dest + CACHE_LINE_SZ;
				if (dest == orig_dest + 0x1000)
					dest = orig_dest;
			}
		}
	} else if (tcfg->misc_flags & (TEST_ENQ | TEST_ENQMEM)) {
		char *dest = tcpu->wq;
		char *orig_dest = dest;

		if (mdest)
			dest = mdest;

		printf("Measure ENQCMD throughput\n");
		for (it = 0; it < max_iter; it++) {
			enqcmd(desc, dest);
			if (tcfg->var_mmio) {
				dest = dest + CACHE_LINE_SZ;
				if (dest == orig_dest + 0x1000)
					dest = orig_dest;
			}
		}
	} else if (tcfg->misc_flags & TEST_DB) {
		printf("Measure UC Doorbell write throughput\n");
		wq_ptr = tcpu->wq;
		for (it = 0; it < max_iter; it++) {
			/* UC doorbell */
			*((volatile uint32_t *)wq_ptr) = 1;
			if (tcfg->var_mmio) {
				wq_ptr = wq_ptr + 64;
				if (wq_ptr == ((char *)tcpu->wq + 0x1000))
					wq_ptr  = tcpu->wq;
			}
		}
	}

	tcpu->cycles += rdtsc() - cyc;
	free(mdest);
}
int
cpu_pin(uint32_t cpu)
{
	cpu_set_t *cpuset;
	size_t cpusetsize;

	cpusetsize = CPU_ALLOC_SIZE(get_nprocs());
	cpuset = CPU_ALLOC(get_nprocs());
	CPU_ZERO_S(cpusetsize, cpuset);
	CPU_SET_S(cpu, cpusetsize, cpuset);

	pthread_setaffinity_np(pthread_self(), cpusetsize, cpuset);

	CPU_FREE(cpuset);

	return 0;
}

static void
test_init_fn(void *arg)
{
	struct tcfg_cpu *tcpu = arg;

	cpu_pin(tcpu->cpu_num);

	test_init_percpu(tcpu);
}

static inline int
init_devtlb(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	char *src = tcpu->misc_b1;
	char *dst = tcpu->misc_b2;
	struct dsa_hw_desc mm_desc = { .opcode = DSA_OPCODE_MEMMOVE,
				   .flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR};
	struct dsa_completion_record *comp;
	int retry;

	INFO_CPU(tcpu, "invalidating dev_tlb\n");

	mm_desc.src_addr = rte_mem_virt2iova(src);
	mm_desc.dst_addr = rte_mem_virt2iova(dst);
	mm_desc.xfer_size = tcfg->blen;

	mm_desc.completion_addr = (uint64_t)(dst + tcfg->blen);
	comp = (struct dsa_completion_record *)(dst + tcfg->blen);
	comp->status = 0;
	__builtin_ia32_sfence();
	/* Init devtlb using memcpy src->dst */
	dsa_desc_submit(tcpu->wq, tcpu->dwq, &mm_desc);

	retry = 0;
	while (comp->status == 0 && retry < MAX_COMP_RETRY)
		retry++;
	if (retry == MAX_COMP_RETRY) {
		ERR("1: %u: Timeout waiting for completion, devtlb_flush\n",
			tcpu->cpu_num);
		tcpu->err = 1;
		return 1;
	}

	if (comp->status != DSA_COMP_SUCCESS) {
		ERR("1: %u: completion status (%d) is not success\n",
			tcpu->cpu_num, comp->status);
		tcpu->err = 1;
		return 1;
	}

	return 0;
}

static inline struct dsa_completion_record *
comp_rec(struct tcfg_cpu *tcpu, int r)
{
	uintptr_t p;

	p = (uintptr_t) (tcpu->tcfg->batch_sz == 1 ? tcpu->comp :
						tcpu->bcomp);

	p += r * comp_rec_size(tcpu);

	return (struct dsa_completion_record *)p;
}

static inline void
reset_cmpltn(struct tcfg_cpu *tcpu, int begin, int end, int ring_size)
{
	int b;
	struct dsa_hw_desc *d;
	struct dsa_completion_record *c;

	b = begin;
	c = comp_rec(tcpu, begin);

	b = begin == 0 ? ring_size - 1 : b - 1;
	d = tcpu->tcfg->op == DSA_OPCODE_BATCH ? tcpu->bdesc : tcpu->desc;

	do {
		b = (b + 1) % ring_size;
		c = comp_rec(tcpu, b);
		if (c->status == 0)
			ERR("Resetting completion - but status is already zero %d\n", b);
		if (tcpu->tcfg->cpu_desc_work)
			init_desc_addr(tcpu, b * tcpu->tcfg->batch_sz,
				d->opcode == DSA_OPCODE_BATCH ? d->desc_count : 1);
		c->status = 0;
	} while (b != end);
}

static __always_inline uintptr_t
next_cache_line(uintptr_t curr_addr)
{
	uintptr_t off = curr_addr & 0xfff;
	uintptr_t base = curr_addr & ~0xfff;

	off += 0x40;
	off &= 0xfff;

	return base + off;
}

static __always_inline void *
incr_portal_addr(struct tcfg_cpu *tcpu, void *curr_mmio)
{
	return tcpu->tcfg->var_mmio ?
		(void *)(next_cache_line((uintptr_t)curr_mmio)) :
		curr_mmio;
}

#define unlikely(x)    __builtin_expect(!!(x), 0)

static __always_inline inline int
submit_b2e(struct tcfg_cpu *tcpu, int begin, int end)
{
	int b;
	struct dsa_hw_desc *desc;
	int ring_size;
	void *wq_reg;
	int ocr;

	ring_size = tcpu->tcfg->nb_desc;
	desc = desc_ptr(tcpu);
	wq_reg = tcpu->wq;
	ocr = tcpu->crdt;

	DEBUG_CPU(tcpu, "submit begin %d end %d\n", begin, end);

	if (!tcpu->dwq) {
		b = begin;

		do {
			if (desc[b].opcode == DSA_OPCODE_DRAIN) {
				/*
				 * sfence is needed before sending a drain desc.
				 * to ensure previous descs are seen by the
				 * device before the drain descriptor
				 */
				__builtin_ia32_sfence();
				tcpu->drain_submitted = rdtsc();
			}
			dsa_desc_submit(wq_reg, tcpu->dwq, &desc[b]);
			if (b == end)
				break;
			b++;
			if (unlikely(b == ring_size))
				b = 0;
		} while (1);

		return begin <= end ? end - begin + 1 :
					ring_size - begin + end + 1;
	}

	b = begin;
	do {
		if (desc[b].opcode == DSA_OPCODE_DRAIN) {
			/*
			 * sfence is needed before sending a drain desc.
			 * to ensure previous descs are seen by the
			 * device before the drain descriptor
			 */
			__builtin_ia32_sfence();
			tcpu->drain_submitted = rdtsc();
		}
		dsa_desc_submit(wq_reg, tcpu->dwq, &desc[b]);
		wq_reg = incr_portal_addr(tcpu, wq_reg);
		if (--tcpu->crdt == 0)
			break;
		if (b == end)
			break;
		b++;
		if (unlikely(b == ring_size))
			b = 0;
	} while (1);

	tcpu->wq = wq_reg;
	return ocr - tcpu->crdt;
}

static void
print_status(uint8_t sc, struct dsa_completion_record *comp)
{
	switch (sc) {

	case DSA_COMP_PAGE_FAULT_NOBOF:
		ERR("fault addr 0x%lx completed %d\n",
			comp->fault_addr, comp->bytes_completed);
		break;

	case DSA_COMP_BATCH_FAIL:
		ERR("batch failed, completed %d\n", comp->bytes_completed);
		break;

	case DSA_COMP_DIF_ERR:
		ERR("diff error, result = 0x%x\n", comp->result);
		break;

	default:
		ERR("Comp status 0x%x\n", sc);
		break;
	}
}

static void
print_batch_comp_err(struct tcfg_cpu *tcpu, int d)
{
	int i;
	struct dsa_hw_desc *desc = tcpu->bdesc + d;
	struct dsa_completion_record *comp = tcpu->comp +
			d * tcpu->tcfg->batch_sz * comp_rec_size(tcpu);

	for (i = 0; i < desc->desc_count; i++)
		print_status(comp->status & 0x3f,
			comp + i * comp_rec_size(tcpu));
}

static void
print_comp_err(struct tcfg_cpu *tcpu, int d)
{
	struct dsa_completion_record *comp = comp_rec(tcpu, d);
	uint8_t sc = comp->status & 0x3f;

	print_status(sc, comp);
	if (sc == DSA_COMP_BATCH_FAIL)
		print_batch_comp_err(tcpu, d);
}

static __always_inline int
poll_comp(struct tcfg_cpu *tcpu, int i, struct poll_cnt *poll_cnt, uint64_t flags)
{
	struct dsa_completion_record *comp = comp_rec(tcpu, i);
	struct dsa_hw_desc *desc;
	int rc;

	rc = poll_comp_common(comp, poll_cnt, flags, MAX_COMP_RETRY);
	desc = desc_ptr(tcpu);
	if (!rc && desc[i].opcode == DSA_OPCODE_DRAIN && poll_cnt && poll_cnt->retry > 0) {
		tcpu->drain_total_cycles += rdtsc() - tcpu->drain_submitted;
		tcpu->nb_drain_completed++;
	}

	tcpu->crdt++;

	return rc;
}

typedef int (*check_fn)(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc);

static int
run_check(struct tcfg_cpu *tcpu, int k, int n, check_fn check_fn)
{
	int d, l;
	struct tcfg *tcfg = tcpu->tcfg;

	d = k;
	l = (k + n) % tcfg->nb_desc;
	do {
		if (check_fn(tcpu, desc_ptr(tcpu) + d))
			return 1;

		d = (d + 1) % tcfg->nb_desc;
		if (d == l)
			break;

	} while (1);

	return 0;
}

static int
check_comp(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	uint64_t flags;
	struct dsa_completion_record *c;
	struct tcfg *tcfg;
	int d;

	tcfg = tcpu->tcfg;
	flags = tcfg->misc_flags;
	d = desc - desc_ptr(tcpu);

	if (poll_comp(tcpu, d, NULL, flags)) {
		c = comp_rec(tcpu, d);
		ERR("d completed %d\n", d);
		if (c->status) {
			ERR("comp (%x)\n", c->status);
			print_comp_err(tcpu, d);
		} else
			ERR("desc[%d] timed out\n", d);
		dump_desc(desc);
		if (desc->opcode == DSA_OPCODE_BATCH) {
			int i;

			for (i = 0; i < desc->desc_count; i++)
				dump_desc(&tcpu->desc[d * tcfg->batch_sz + i]);
		}
		tcpu->err = 1;
		return 1;
	}

	return 0;
}

static int
check_result_one(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	int i;
	struct dsa_completion_record *comp =
			desc->opcode == DSA_OPCODE_BATCH ? tcpu->bcomp :
							tcpu->comp;
	uint32_t k = desc->opcode == DSA_OPCODE_BATCH ? desc - tcpu->bdesc :
							desc - tcpu->desc;

	PTR_ADD(comp, k * comp_rec_size(tcpu));

	switch (desc->opcode) {

	case DSA_OPCODE_COMPARE:
	case DSA_OPCODE_COMPVAL:
		if (comp->result != 0) {
			ERR("%d: buf compare mismatch desc(%d)\n",
				tcpu->cpu_num, k);
			tcpu->err = 1;
		}
		break;

	case DSA_OPCODE_DIF_UPDT:
		if (comp->status == DSA_COMP_DIF_ERR) {
			ERR("diff error, dif status %u\n", comp->dif_status);
			tcpu->err = 1;
		}
		break;

	case DSA_OPCODE_COPY_CRC:
		if (comp->crc_val != tcpu->crc[k]) {
			ERR("crc mismatch desc %d\n", k);
			tcpu->err = 1;
		}
		break;

	case DSA_OPCODE_BATCH:
		for (i = 0; i < desc->desc_count; i++)
			if (check_result_one(tcpu,
				&tcpu->desc[k * tcpu->tcfg->batch_sz + i]))
				return tcpu->err;
	}

	return tcpu->err;
}

static inline void
submit_test_desc(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	int nb_desc = tcfg->nb_desc;
	uint32_t it;
	int d;
	uint32_t tsc_cnt;
	bool inf;
	uint32_t flags;

	tcfg = tcpu->tcfg;
	tcpu->cycles = 0;
	tsc_cnt = 0;

	inf = tcfg->iter == ~0U;
	flags = tcfg->misc_flags;

	tcpu->min_cyc = ~0ULL;
	tcpu->max_cyc = 0;

	if (!iommu_disabled()) {

		test_barrier(tcfg, 0);
		if (tcpu == &tcfg->tcpu[0])
			tcpu->err = iotlb_invd(tcfg);
		if (test_barrier(tcfg, tcpu->err))
			return;
	}

	do_cache_ops(tcpu);

	test_barrier(tcfg, 0);

	INFO_CPU(tcpu, "Running Latency test\n");

	for (it = 0; inf || it < tcfg->iter; it++) {
		uint64_t tstart, tend;
		struct poll_cnt poll_cnt;
		int it_cnt;

		reset_cmpltn(tcpu, 0, nb_desc - 1, nb_desc);
		__builtin_ia32_sfence();

		tcpu->err = !iommu_disabled() &&  (flags & DEVTLB_INIT_FLAG) ?
							init_devtlb(tcpu) : 0;
		if (tcpu->err)
			return;

		it_cnt = 0;

		tstart = rdtsc();

		submit_b2e(tcpu, 0, nb_desc - 1);

		for (d = nb_desc - 1; d >= 0; d--) {

			if (unlikely(poll_comp(tcpu, d, &poll_cnt, flags))) {

				tcpu->err = 1;

				if (poll_cnt.retry > MAX_COMP_RETRY) {
					ERR("Retry limit exceeded\n");
					goto error1;
				}

				ERR("Iteration (%d), comp (%d)\n", it, d);
				print_comp_err(tcpu, d);
				goto error1;
			}

			if (poll_cnt.retry) {
				tend = rdtsc();
				it_cnt = 1;
			}

			if (flags & CPL_UMWAIT) {
				if (poll_cnt.mwait > 1)
					tcpu->mwait_cnt_arr[2]++;
				else
					tcpu->mwait_cnt_arr[poll_cnt.mwait]++;

				if (!poll_cnt.retry)
					tcpu->monitor_cnt_arr[0]++;
				if (poll_cnt.monitor != poll_cnt.mwait)
					tcpu->monitor_cnt_arr[1]++;

				tcpu->os_dline_exp += poll_cnt.os_dline_exp;
			}
		}

		if (it_cnt && it >= tcfg->warmup_iter) {

			tcpu->min_cyc = min(tcpu->min_cyc, tend - tstart);
			tcpu->max_cyc = max(tcpu->max_cyc, tend - tstart);

			if (tend - tstart < 5 * tcpu->min_cyc) {
				tcpu->cycles += tend - tstart;
				tsc_cnt++;
			}

			if (tsc_cnt && inf && !(tsc_cnt % INF_LOOP_SHOW_STATS)) {
				printf("avg cycles %lu min %lu max %lu\n",
					tcpu->cycles/tsc_cnt, tcpu->min_cyc, tcpu->max_cyc);
				tcpu->min_cyc = ~0U;
				tcpu->max_cyc = 0;
				tcpu->cycles = 0;
				tsc_cnt = 0;
			}
		}

		tcpu->curr_stat.iter++;
	}

	if (tsc_cnt)
		tcpu->cycles /= tsc_cnt;

	INFO_CPU(tcpu, "Latency test done\n");

	tcpu->err = 0;
	return;

error1:
	tcpu->err = 1;
}

static __always_inline int
do_single_iter(struct tcfg_cpu *tcpu, int nb_desc)
{
	int k;	/* completed descriptor count */
	int s;
	struct dsa_completion_record *c;

	k = 0;

	/*
	 * the prevous invocation submitted [0..n] where
	 * n = min(nb_desc - 1, tcpu->qd - 1)
	 *
	 * if nb_desc <= qd:
	 *	the next descriptor to submit after
	 *	desc[0] completes is desc[0]
	 * else
	 *	submit desc[tcpu->qd]
	 */
	s = nb_desc <= tcpu->qd ? 0 : tcpu->qd;

	while (k < nb_desc) {
		struct poll_cnt poll_cnt = { 0 };
		int prev_k;

		if (poll_comp(tcpu, k, &poll_cnt, tcpu->tcfg->misc_flags)) {
			c = comp_rec(tcpu, k);
			if (c->status != DSA_COMP_SUCCESS) {
				ERR("%d comp status %d\n", k, c->status);
				tcpu->err = 1;
				return 1;
			}

		}

		tcpu->curr_stat.retry += poll_cnt.retry;
		tcpu->curr_stat.mwait_cycles += poll_cnt.mwait_cycles;

		prev_k = k;
		c = comp_rec(tcpu, k);
		c->status = 0;
		k++;
		while (k < nb_desc) {
			uint8_t tstatus;

			c = comp_rec(tcpu, k);
			tstatus = c->status;
			if (tstatus == 0)
				break;

			if (tstatus > 1) {
				ERR("desc(%d) Unexpected status 0x%x\n", k, tstatus);
				tcpu->err = 1;
				return 1;
			}

			k++;
			tcpu->crdt++;
			c->status = 0;
		}


		__builtin_ia32_sfence();
		submit_b2e(tcpu, s, (s + k - prev_k - 1) % nb_desc);
		s += k - prev_k;
		s %= nb_desc;
	}

	return 0;
}

static inline void
submit_test_desc_loop(struct tcfg_cpu *tcpu)
{
	uint32_t i;
	int d;
	struct tcfg *tcfg;
	bool inf;
	int nb_desc;

	tcfg = tcpu->tcfg;
	tcpu->cycles = 0;
	tcpu->curr_stat.retry = 0;
	nb_desc = tcfg->nb_desc;

	reset_cmpltn(tcpu, 0, nb_desc - 1, nb_desc);
	__builtin_ia32_sfence();

	/* submit as many descs as there would be in the WQ when do_single_iter() returns */
	submit_b2e(tcpu, 0, min(nb_desc - 1, tcpu->qd - 1));

	do_cache_ops(tcpu);

	test_barrier(tcfg, 0);

	INFO_CPU(tcpu, "Running BW test\n");

	inf = tcfg->iter == ~0U;

	tcpu->curr_stat.iter = 0;
	tcpu->tstart = rdtsc();
	for (i = 0; !tcfg->stop && (inf || i < tcfg->iter) ; i++) {
		if (do_single_iter(tcpu, nb_desc)) {
			ERR("Error iteration: %d\n", i);
			goto error2;
		}
		tcpu->curr_stat.iter++;
	}
	tcpu->tend = rdtsc();

	if (tcfg->iter)
		tcpu->cycles = (tcpu->tend - tcpu->tstart)/tcfg->iter;

	d = 0;
	while (d < tcpu->qd) {
		while (comp_rec(tcpu, d)->status == 0)
			;
		comp_rec(tcpu, d)->status = 0;
		d++;
	}

	INFO_CPU(tcpu, "BW test done\n");
	tcpu->err = 0;
error2:
	return;
}

static void
submit_test_desc_common(struct tcfg_cpu *tcpu)
{
	tcpu->tcfg->loop ? submit_test_desc_loop(tcpu) :
			submit_test_desc(tcpu);
}

static void
faultin_range(char *buf, uint64_t blen, uint64_t bstride, uint32_t nb_bufs)
{
	uint32_t i;

	for (i = 0; i < nb_bufs; i++) {
		char *b;

		for (b = buf; b < buf + blen; b = b + 4096) {
			volatile char *v = (volatile char *)b;
			*v;
		}

		buf += bstride;
	}
}

static void
do_desc_work(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	int nb_desc;
	int rc;
	int b;
	int s;

	nb_desc = tcfg->nb_desc;
	tcpu->crdt = tcpu->qd;

	if (tcfg->pg_size == 0 && tcfg->proc) {
		int i;

		/* mmap(MAP_POPULATE) but generates a fault on write after fork */
		for (i = 0; i < tcfg->op_info->nb_buf; i++)
			faultin_range((char *)tcpu->b[i], tcfg->blen_arr[i],
				tcfg->bstride_arr[i], tcfg->nb_bufs);
	}

	INFO_CPU(tcpu, "Preparing descriptors\n");
	test_prep_desc(tcpu);

	INFO_CPU(tcpu, "Submitting descriptors\n");
	for (b = 0; b < nb_desc; b = b + s) {
		int e;

		e = min(b + tcpu->qd - 1, nb_desc - 1);
		s = submit_b2e(tcpu, b, e);

		rc = run_check(tcpu, b, s, check_comp);
		if (rc)
			return;

		rc = run_check(tcpu, b, s, check_result_one);
		if (rc)
			return;
	}

	INFO_CPU(tcpu, "Verifying descriptors\n");
	tcpu->err = verify_buf(tcpu);
	if (tcpu->err)
		return;

	submit_test_desc_common(tcpu);
}

static void *
test_run_fn(void *arg)
{
	struct tcfg_cpu *tcpu = arg;
	struct tcfg *tcfg = tcpu->tcfg;
	bool do_sub_rate;

	cpu_pin(tcpu->cpu_num);

	if (!tcpu->tcfg->dma) {
		test_memcpy(arg);
		return 0;
	}

	do_sub_rate = tcfg->misc_flags &
			(TEST_M64 | TEST_DB | TEST_M64MEM |
			TEST_ENQ | TEST_ENQMEM);

	if (tcfg->op == DSA_OPCODE_NOOP && do_sub_rate)
		work_sub_rate_test(tcpu);
	else
		do_desc_work(tcpu);

	return 0;
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

static void *
test_fn(void *arg)
{
	struct tcfg_cpu *tcpu = arg;
	int err;

	test_init_fn(arg);
	err = test_barrier(tcpu->tcfg, tcpu->err);

	if (tcpu->err)
		ERR("test init failed: cpu %d\n", tcpu->cpu_num);

	if (err) {
		if (tcpu->tcfg->proc)
			exit(0);
		return NULL;
	}

	test_run_fn(arg);

	dunmap_per_cpu(tcpu);
	if (tcpu->tcfg->proc)
		exit(0);

	return NULL;
}

static int
test_run(struct tcfg *tcfg)
{
	int i, err = 0;

	for (i = 0; i < tcfg->nb_cpus; i++) {

		if (tcfg->proc) {
			tcfg->tcpu[i].pid = fork();
			if (tcfg->tcpu[i].pid == -1) {
				ERR("Failed to create child process\n");
				err = -errno;
				goto err_ret;
			}
			if (tcfg->tcpu[i].pid == 0)
				test_fn(&tcfg->tcpu[i]);
		} else {
			err = pthread_create(&tcfg->tcpu[i].thread, NULL, test_fn,
				&tcfg->tcpu[i]);
			if (err) {
				ERR("Failed to create thread\n");
				goto err_ret;
			}
		}
	}

	if (tcfg->iter == ~0U) {
		uint64_t iter_bytes =  tcfg->nb_bufs * tcfg->blen;

		err = false;
		while (!err) {
			float bw;
			struct iter_stat is;

			sleep(tcfg->tval_secs);
			iter_count(tcfg, &is);

			bw = (is.iter * iter_bytes)/(1E9 * tcfg->tval_secs);

			for (i = 0, err = false; i < tcfg->nb_cpus; i++) {
				struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

				err = !!tcpu->err;
				if (err) {
					ERR("Err on cpu %d: cpu num %d err %d\n", i, tcpu->cpu_num, tcpu->err);
					break;
				}
			}

			if (err) {
				tcfg->stop = true;
				continue;
			}

			tcfg->retry = is.retry / tcfg->nb_cpus;
			tcfg->mwait_cycles = is.mwait_cycles / tcfg->nb_cpus;
			calc_cpu_for_sec(tcfg, tcfg->tval_secs);

			fprintf(stdout, "BW %f GB cpu util %f\n", bw, tcfg->cpu_util);
		}
	}

	for (i = 0; i < tcfg->nb_cpus; i++) {
		if (tcfg->proc) {
			if (tcfg->tcpu[i].pid > 0)
				waitpid(tcfg->tcpu[i].pid, NULL, 0);
		} else
			pthread_join(tcfg->tcpu[i].thread, NULL);
	}

	for (i = 0; !err && i < tcfg->nb_cpus; i++)
		if (tcfg->tcpu[i].err)
			err = tcfg->tcpu[i].err;

err_ret:
	return err;
}

int
main(int argc, char **argv)
{
	int err;
	int i;
	struct tcfg tcfg = {
		.blen = 4 * 1024,
		.bl_idx = 0,
		.nb_bufs = 32,
		.drain_desc = 0,
		.pg_size = 0,
		.wq_type = 0,
		.batch_sz = 1,
		.iter = 1000,
		.warmup_iter = 999,
		.fill = 0xc0debeefc0deabcd,
		.op = DSA_OPCODE_MEMMOVE,
		.dma = 1,
		.misc_flags = 0,
		.verify = 1,
		.flags_nth_desc = 1,
		.flags_cmask = -1,
		.flags_nth_desc = 1,
		.flags_smask = 0,
		.tval_secs = 4,
		.numa_node_default = { -1, -1, -1 },
		.place_op = { OP_FLUSH, OP_FLUSH, OP_FLUSH },
		.access_op = { OP_WRITE, OP_WRITE, OP_WRITE },
		.delta = 100,
		.pg_size = 0,
	};

	for (i = 0; i < argc; i++)
		printf("%s ", argv[i]);
	printf("\n");

	log_init(&log_ctx, "dsa_perf_micros", "DSA_PERF_MICROS_LOG_LEVEL");

	err = do_options(argc, argv, &tcfg);
	if (err != 0)
		goto err_ret;

	if (tcfg.driver == USER && tcfg.pg_size == 0)
		tcfg.pg_size = 2;

	err = test_init_global(&tcfg);
	if (err != 0)
		goto err_ret;

	print_tcfg(&tcfg);

	err = test_run(&tcfg);
	if (err) {
		ERR("test run failed\n");
		goto err_ret;
	}

	do_results(&tcfg);

	if (!tcfg.loop) {
		struct tcfg_cpu *tcpu = &tcfg.tcpu[0];

		printf("Number of monitors done: [0]:%d, [1]:%d\n",
			tcpu->monitor_cnt_arr[0], tcpu->monitor_cnt_arr[1]);
		printf("Number of mwaits done: [0]:%d, [1]:%d, [> 1]:%d\n",
			tcpu->mwait_cnt_arr[0], tcpu->mwait_cnt_arr[1],
			tcpu->mwait_cnt_arr[2]);
		printf("Number of OS deadline mwaits: %d\n", tcpu->os_dline_exp);
	}

	printf("GB per sec = %f latency(cycles) = %f, %f ns,"
		" cycles/sec =%ld cpu %f kopsrate = %d\n",
		tcfg.bw, tcfg.latency, (tcfg.latency * 1E9)/tcfg.cycles_per_sec,
		tcfg.cycles_per_sec, tcfg.cpu_util, tcfg.ops_rate);

	if (tcfg.drain_desc) {
		double drain_usec = ((1.0 * tcfg.drain_lat)/tcfg.cycles_per_sec) * 1000000;

		printf("Drain desc latency = %lu cycles | %f uSec\n", tcfg.drain_lat, drain_usec);
	}

err_ret:
	test_free(&tcfg);

	return !(err == 0);
}
