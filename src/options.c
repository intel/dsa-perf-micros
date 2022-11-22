// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/sysinfo.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>
#include <errno.h>
#include <linux/idxd.h>

#include "common.h"
#include "options.h"
#include "util.h"

struct parse_info {
	int *nb_node;
	char a[NUM_ADDR_MAX], p[NUM_ADDR_MAX];
	int nb_a, nb_p;
};

struct cpu_wq_info {
	uint32_t c;
	char *d;
	int q;
	int g;
};

#define MAX_DELTA_TRANSFER_SIZE 0x80000
#define MAX_TRANSFER_SIZE	0x80000000

#define OP_INFO_ADDR(op_suffix, aname1, aname2, aname3, sz, ir) \
	[DSA_OPCODE_##op_suffix] = {\
		.valid = true,\
		.b_off = {\
			offsetof(struct tcfg_cpu, aname1),\
			offsetof(struct tcfg_cpu, aname2),\
			offsetof(struct tcfg_cpu, aname3) },\
		.max_transfer_size = sz,\
		.init_req = ir}

static struct op_info op_info[] = {
	OP_INFO_ADDR(NOOP, addr_none, addr_none, addr_none, 0, false),
	OP_INFO_ADDR(MEMMOVE, src, dst, addr_none, 0, false),
	OP_INFO_ADDR(MEMMOVE, src, dst, addr_none, 0, false),
	OP_INFO_ADDR(MEMFILL, dst, addr_none, addr_none, 0, false),
	OP_INFO_ADDR(COMPARE, src1, src2, addr_none, 0, true),
	OP_INFO_ADDR(COMPVAL, src, addr_none, addr_none, 0, true),
	OP_INFO_ADDR(CR_DELTA, src1, src2, delta, MAX_DELTA_TRANSFER_SIZE, true),
	OP_INFO_ADDR(AP_DELTA, delta, dst, addr_none, 0, false),
	OP_INFO_ADDR(DUALCAST, src, dst1, dst2, 0, false),
	OP_INFO_ADDR(CRCGEN, src, addr_none, addr_none, 0, false),
	OP_INFO_ADDR(COPY_CRC, src, dst, addr_none, 0, false),

	/* initialized in prep */
	OP_INFO_ADDR(DIF_CHECK, src, addr_none, addr_none, 0, false),
	OP_INFO_ADDR(DIF_INS, src, dst, addr_none, 0, false),
	OP_INFO_ADDR(DIF_STRP, src, dst, addr_none, 0, false),
	OP_INFO_ADDR(DIF_UPDT, src, dst, addr_none, 0, false),

	OP_INFO_ADDR(CFLUSH, dst, addr_none, addr_none, 0, false)
};

#define ARR_IDX(c) ((c) - 'A')

static const int place_map[256] = { [ARR_IDX('N')] = OP_NONE,
						[ARR_IDX('P')] = OP_FETCH,
						[ARR_IDX('D')] = OP_DEMOTE,
						[ARR_IDX('F')] = OP_FLUSH,
					};
static const int access_map[256] = { [ARR_IDX('N')] = OP_NONE,
					[ARR_IDX('R')] = OP_READ,
					[ARR_IDX('W')] = OP_WRITE,
				};

static
void print_usage(void)
{
	printf(
	"\t-a                   ; Shuffle descriptors, use to test random strides between addresses in\n"
	"\t                       desc. addresses v/s constant strides.\n"
	"\t-b <batch_size>      ; Use batch descriptors with batch size descriptors in a batch.\n"
	"\t-B                   ; PCI device/resource+offset_into_mmio list to mmap memory from\n"
	"\t                       e.g., m,Bus:Device.Function/resource0+4096 => memory is src, B:D.F/resource0+4096 is dst\n"
	"\t-c                   ; Increment portal address between descriptors.\n"
	"\t-C                   ; Include descriptor modification cycles in CPU utilization measurement\n"
	"\t-D <delta %%>         ; Delta (specified as a percentage) between buffers for delta create and delta apply\n"
	"\t-e <block length>    ; Block len [0-3] for dif operations\n"
	"\t-f                   ; Set the cache control flag in descriptors\n"
	"\t-F <flag_bits_to_clear:flag_bits_to_set:every_nth_desc>\n"
	"\t                       e.g., -F 0xFFFFF7:0x8:4 to clear Addr2_TC flag and set RCR=1 on every 4th descriptor\n"
	"\t-h                   ; Print this message\n"
	"\t-i <iterations>      ; The number of iterations to run the test for, use i-1 for continuous run (periodic BW/Latency output)\n"
	"\t-j                   ; deprecated parameter - default behavior\n"
	"\t-k <CPU list>        ; List of CPUs (e.g., -k0, -k0,1,2,3, -k0-2, -k0-2,3)\n"
	"\t-K <CPU/WQ list>     ; List of CPUs and associated WQ (e.g., [0,1]@dsa0,0,[2-3]@dsa0,1)\n"
	"\t-l <0/1>             ; Use large pages, 0 for 2M, 1 for 1G.\n"
	"\t-m                   ; Use CPU to implement opcodes.\n"
	"\t-n <buffer count>    ; Buffer count\n"
	"\t-o <opcode>          ; DSA opcode\n"
	"\t-0 <offset list>     ; Buffer address offsets from start of 4K page in decimal (-Ob1_off,b2_off,b3_off)\n"
	"\t-P                   ; Use processes instead of threads\n"
	"\t-q <queue depth>     ; Queue depth for dedicated WQ, can be > WQ size (use with -j)\n"
	"\t-s <size>            ; Transfer size in bytes, can use k,m,g to specify KiB/MiB/GiB (e.g., -b 200m)\n"
	"\t-S <Numa Node list>  ; Numa node IDs fo src(b1)/dst(b2)/b3 allocation, specify -1 for same node\n"
	"\t                     ; as CPU (e.g., -S-1,1 - same node as CPU for src, node 1 for dst)\n"
	"\t-t <stride>          ; Stride between buffer start addresses\n"
	"\t-T <time in sec>     ; Time interval for BW measurement, use with -i-1\n"
	"\t-u<engine count>     ; Use VFIO/UIO device, engine count is optional\n"
	"\t-w <0/1>             ; WQ type, 0 => dedicated, 1 => shared\n"
	"\t-W<warmup iterations> ; deprecated prameter - check sample_command_lines.rst for latency measurement command line\n"
	"\t-x<misc_flags>       ; bit0 => deprecated - check sample_command_lines.rst for latency measurement command line\n"
	"\t                       bits[1:5]: movdir64/enqcmd submission rate test\n"
	"\t                       bit[7:8] => pause(7)/umwait(8) in completion wait (use for latency measurement)\n"
	"\t                       bits[9:31] => unused\n"
	"\t-v                   ; Verify result (0 => disable, 1 => enable, default is enable)\n"
	"\t-y                   ; Comma seperated list used to specify how DSA operands (None/Read/Write) are\n"
	"\t                       accessed by the CPU before descriptors are issued.\n"
	"\t-Y                   ; Convert last descriptor to drain descriptor.\n"
	"\t-z                   ; Comma separated list of directives for data placement for respective buffers.\n"
	"\t                       the specifiers are -P (fetch into the L1 cache), -D (demote to LLC),\n"
	"\t                       -F (flush to memory)\n");
}

static char *
make_sysfs_filename(char *bdf)
{
	static char tmp[] = "/sys/bus/pci/devices/0000:";
	int lf;
	char *f;

	if (!bdf)
		return NULL;

	lf = snprintf(NULL, 0, "%s%s", tmp, bdf);

	f = calloc(1, lf + 1);
	if (!f)
		return NULL;

	snprintf(f, lf + 1, "%s%s", tmp, bdf);

	return f;
}

static int
parse_bdf_list(struct mmio_mem *mmio_mem, int *mmio_idx, char *optarg)
{
	char *bdf_offset;
	int n;
	int bi;

	bi = 0;

	while (sscanf(optarg,  "%m[^,]%n", &bdf_offset, &n) == 1 && bi < 3) {
		char *bdf;
		int offset;

		if (strcmp(bdf_offset, "m") != 0) {
			int j;
			int lf;

			sscanf(bdf_offset,  "%m[^+]%d", &bdf, &offset);

			mmio_mem[bi].bfile = make_sysfs_filename(bdf);
			free(bdf);
			if (mmio_mem[bi].bfile == NULL)
				return -ENOMEM;

			lf = strlen(mmio_mem[bi].bfile);
			mmio_mem[bi].mmio_offset = offset;

			for(j = 0; j < bi; j++) {
				if (mmio_mem[j].bfile &&
					!strncmp(mmio_mem[bi].bfile, mmio_mem[j].bfile, lf)) {
					mmio_idx[bi] = j;
					goto next_bdf;
				}
			}

			mmio_idx[bi] = bi;
		}
 next_bdf:
		free(bdf_offset);
		optarg += n;
		if (*optarg != ',')
			break;
		optarg++;
		bi++;
	}

	return 0;
}

static int
parse_blen(uint64_t *blen, char *str)
{
	char c;
	uint32_t m;

	*blen = 0;
	c = toupper(str[strlen(str) - 1]);

	switch (c) {
	case 'K':
		m = 1024;
		break;

	case 'M':
		m = 1024 * 1024;
		break;

	case 'G':
		m = 1024 * 1024 * 1024;
		break;

	default:
		m = 1;
	}

	if (m != 1)
		str[strlen(str) - 1] = '\0';

	*blen = strtoul(str, NULL, 0);
	*blen *= m;

	return 0;
}

static inline void
swap(int *c1, int *c2)
{
	int t = *c1;
	*c1 = *c2;
	*c2 = t;
}

static int
parse_cpu_list(uint32_t *all_cpus, const char *str)
{
	unsigned int n;
	int i;
	int r;
	int c1, c2;
	int err;

	err = 0;

	do {
		n = strcspn(str, "-,");

		if (n == strlen(str))
			break;

		if (str[n] == '-') {

			r = sscanf(str, "%d%*c%d", &c1, &c2);
			if (r < 2) {
				ERR("1 invalid str %s\n", str);
				err = -EINVAL;
				goto ret;
			}
			if (c1 > c2)
				swap(&c1, &c2);

			if (c1 >= get_nprocs()) {
				ERR("%d >= num cpus %d\n", c1, get_nprocs());
				err = -EINVAL;
				goto ret;
			}

			for (i = c1; i <= c2; i++) {
				if (all_cpus[i] == 1) {
					err = -EINVAL;
					goto ret;
				}
				all_cpus[i] = 1;
			}

			str = &str[n] + 1;
		} else if (str[n] == ',') {

			r = sscanf(str, "%d%*c", &c1);
			if (r == 0) {
				r = sscanf(str, "%*c%d", &c1);
				if (r == 0) {
					ERR("2 invalid str %s\n", str);
					err = -EINVAL;
					goto ret;
				}
			}

			if (r != 0) {
				if (c1 >= get_nprocs()) {
					err = -EINVAL;
					goto ret;
				}

				all_cpus[c1] = 1;
			}

			str = &str[n] + 1;
		}

	} while (1);

	r = sscanf(str, "%d", &c1);
	/* str can be a blank string => r = EOF */
	if (r != EOF && r != 0) {
		if (c1 >= get_nprocs()) {
			err = -EINVAL;
			goto ret;
		}
		all_cpus[c1] = 1;
	}

ret:
	return err;
}

static int
parse_cpu_param(struct cpu_wq_info *cpus, uint32_t *nb_cpus, const char *str)
{
	int max_cpus = get_nprocs();
	uint32_t *all_cpus;
	int i;
	int err;

	all_cpus = calloc(max_cpus, sizeof(*all_cpus));

	if (!all_cpus)
		return -ENOMEM;

	err = parse_cpu_list(all_cpus, str);

	if (!err) {
		for (i = 0; i < max_cpus; i++) {
			if (all_cpus[i]) {
				cpus[*nb_cpus].c = i;
				cpus[*nb_cpus].q = -1;
				cpus[*nb_cpus].d = NULL;
				*nb_cpus += 1;
			}
		}
	}

	free(all_cpus);
	return err;
}

static int
parse_cpu_wq_param(struct cpu_wq_info *cpus, uint32_t *nb_cpus, char *str)
{
	char *start;
	char *end;
	uint32_t *all_cpus, *wqs;
	char **devs;
	int i;
	int q;
	char *pd;
	int err;

	all_cpus = calloc(get_nprocs(), sizeof(*all_cpus));
	if (!all_cpus)
		return -ENOMEM;

	devs = calloc(get_nprocs(), sizeof(*devs));
	if (!devs) {
		free(all_cpus);
		return -ENOMEM;
	}

	wqs = calloc(get_nprocs(), sizeof(*all_cpus));
	if (!wqs) {
		free(devs);
		free(all_cpus);
		return -ENOMEM;
	}

	err = 0;
	start = str;

	while ((start += strcspn(start, "[")) && *start) {
		uint32_t *cpus;

		cpus = calloc(get_nprocs(), sizeof(*cpus));
		if (!cpus) {
			err = -ENOMEM;
			break;
		}
		end = start;
		if (*start == '[') {
			end += strcspn(start, "]");
			if (*end == ']') {
				char *str = strndup(start + 1, end - start - 1);

				err = parse_cpu_list(cpus, str);
				free(str);
				if (err) {
					ERR("err is set\n");
					free(cpus);
					break;
				}
			}
		}

		start += strcspn(start, "@") + 1;
		if (sscanf(start, "%m[^,]%*c%d", &pd, &q) < 2) {
			err = -EINVAL;
			free(cpus);
			break;
		}


		for (i = 0; pd && i < get_nprocs(); i++) {
			if (cpus[i] != 0) {
				all_cpus[i] = 1;
				devs[i] = strdup(pd);
				wqs[i] = q;
			}
		}

		free(pd);
		free(cpus);
	}

	if (!err) {
		for (i = 0; i < get_nprocs(); i++) {
			if (all_cpus[i] != 0) {
				cpus[*nb_cpus].c = i;
				cpus[*nb_cpus].d = devs[i];
				cpus[*nb_cpus].q = wqs[i];
				(*nb_cpus)++;
			}
		}
	}

	free(devs);
	free(wqs);
	free(all_cpus);

	if (*nb_cpus == 0)
		return -EINVAL;

	return err;
}

static int
parse_numa_node(int *nodes, char *optarg)
{
	return sscanf(optarg, "%d,%d,%d", &nodes[0], &nodes[1], &nodes[2]);
}

static void
update_dif_length(struct tcfg *tc)
{
	int nb_blocks;

	nb_blocks = tc->blen/tc->bl_len;

#define UPDT_BLEN_STRD(l, s, nb_blocks) \
do {\
	(l) += (nb_blocks) * 8;\
	if ((s) < (l))\
		(s) = (l);\
} while (0)

	switch (tc->op) {

	case DSA_OPCODE_DIF_CHECK:
		UPDT_BLEN_STRD(tc->blen_arr[0], tc->bstride_arr[0], nb_blocks);
		break;

	case DSA_OPCODE_DIF_INS:
		UPDT_BLEN_STRD(tc->blen_arr[1], tc->bstride_arr[1], nb_blocks);
		break;

	case DSA_OPCODE_DIF_STRP:
		UPDT_BLEN_STRD(tc->blen_arr[0], tc->bstride_arr[0], nb_blocks);
		/*
		 * TODO: Add ref. to erratum after errata are published
		 */
		UPDT_BLEN_STRD(tc->blen_arr[1], tc->bstride_arr[1], nb_blocks);
		break;

	case DSA_OPCODE_DIF_UPDT:
		UPDT_BLEN_STRD(tc->blen_arr[0], tc->bstride_arr[0], nb_blocks);
		UPDT_BLEN_STRD(tc->blen_arr[1], tc->bstride_arr[1], nb_blocks);
	}
}

static uint32_t
calc_delta_rec_size(struct tcfg *tcfg)
{
	uint32_t nb_cmp;

	nb_cmp = tcfg->blen/8;
	nb_cmp = (nb_cmp * tcfg->delta)/100;

	if (nb_cmp == 0)
		nb_cmp = 1;

	return nb_cmp * sizeof(struct delta_rec);
}

static void
fixup_options(struct tcfg *tc, struct parse_info *pi)
{
	int i;

	switch (tc->op) {

	case DSA_OPCODE_MEMFILL:
		for (i = 0; i < tc->nb_numa_node; i++) {
			/* S1,-1 => S-1 */
			if (pi->nb_node[i] == 2) {
				pi->nb_node[i] = 1;
				tc->numa_node[i][0] = tc->numa_node[i][1];
			}
		}
		break;

	case DSA_OPCODE_COMPARE:
		/* -yR => -yR,R */
		if (pi->nb_a == 1) {
			pi->nb_a = 2;
			pi->a[1] = pi->a[0];
		}

		/* -zF => -zF,F */
		if  (pi->nb_p == 1) {
			pi->nb_p = 2;
			pi->p[1] = pi->p[0];
		}

		for (i = 0; i < tc->nb_numa_node; i++) {
			/* -S-1 => -S-1,-1 */
			if (pi->nb_node[i] == 1) {
				pi->nb_node[i] = 2;
				tc->numa_node[i][1] = tc->numa_node[i][0];
			}
		}
		break;

	case DSA_OPCODE_DUALCAST:

		/* -zD,F => -zD,F,F */
		if  (pi->nb_p == 2) {
			pi->nb_p = 3;
			pi->p[2] = pi->p[1];
		}

		/* -yR,W => -yR,W,W */
		if  (pi->nb_a == 2) {
			pi->nb_a = 3;
			pi->a[2] = pi->a[1];
		}

		for (i = 0; i < tc->nb_numa_node; i++) {
			/* -S-1,1 => -S-1,1,1 */
			if (pi->nb_node[i] == 2) {
				pi->nb_node[i] = 3;
				tc->numa_node[i][2] = tc->numa_node[i][1];
			}
		}
		break;

	case DSA_OPCODE_CR_DELTA:

		/* -zD,F => -zD,D,F */
		if  (pi->nb_p == 2) {
			pi->nb_p = 3;
			pi->p[2] = pi->p[1];
			pi->p[1] = pi->p[0];
		}

		/* -yR,W => -yR,R,W */
		if  (pi->nb_a == 2) {
			pi->nb_a = 3;
			pi->a[2] = pi->a[1];
			pi->a[1] = pi->a[0];
		}

		for (i = 0; i < tc->nb_numa_node; i++) {
			/* -S-1,1 => -S-1,-1,1 */
			if (pi->nb_node[i] == 2) {
				pi->nb_node[i] = 3;
				tc->numa_node[i][2] = tc->numa_node[i][1];
				tc->numa_node[i][1] = tc->numa_node[i][0];
			}
		}
		break;

	default:
		break;
	}

	if (tc->iter == -1 && tc->tval_secs == 0)
		tc->tval_secs = TIME_DELAY_SEC;
}

static void
init_tc_numa_node(int (*n)[NUM_ADDR_MAX])
{
	int i;

	for (i = 0; i < NUM_ADDR_MAX; i++)
		n[0][i] = -1;
}

static int
do_getopt(int argc, char **argv, struct tcfg *tc, struct parse_info *pi, struct cpu_wq_info *cpu_idx)
{
	char *a = pi->a;
	char *p = pi->p;
	int i;
	int nb_s;
	int opt;
	uint64_t op;
	int n;
	unsigned int nb_k, nb_K;
	int rc;

	n = 0;
	nb_k = nb_K = 0;
	while ((opt = getopt(argc, argv, "b:e:i:k:l:n:o:q:s:t:u::v:w:x:y:z:B:D:F:K:"
			"L:M:O:S:T:W:achfjmCPY")) != -1) {
		int nb_a, nb_p;

		switch (opt) {

		case 'a':
			tc->shuffle_descs = true;
			break;

		case 'b':
			tc->batch_sz = strtoul(optarg, NULL, 0);
			break;

		case 'B':
			rc = parse_bdf_list(tc->mmio_mem, tc->mmio_fd_idx, optarg);
			if (rc)
				return rc;
			break;

		case 'c':
			tc->var_mmio = 1;
			break;

		case 'C':
			tc->cpu_desc_work = true;
			break;

		case 'D':
			tc->delta = strtoul(optarg, NULL, 0);
			if (tc->delta > 100) {
				ERR("Delta %d exceeds max allowed (100)\n", tc->delta);
				return -EINVAL;
			}
			break;

		case 'e':
			tc->bl_idx = strtoul(optarg, NULL, 0);
			break;

		case 'f':
			tc->ccmask = IDXD_OP_FLAG_CC;
			break;

		case 'F':
			nb_s = sscanf(optarg, "%x:%x:%u",
					&tc->flags_cmask,
					&tc->flags_smask,
					&tc->flags_nth_desc);
			if (nb_s != 2 && nb_s != 3) {
				ERR("Failed to parse flags mask\n");
				return -EINVAL;
			}
			break;

		case 'h':
			print_usage();
			exit(0);

		case 'i':
			tc->iter = strtoul(optarg, NULL, 0);
			break;

		case 'j':
			printf("-j option is deprecated (default behavior)\n");
			break;

		case 'k':
			if (nb_K) {
				ERR("Only one of -k or -K can be specified\n");
				return -EINVAL;
			}

			if (parse_cpu_param(cpu_idx, &nb_k, optarg) != 0) {
				ERR("Failed to parse CPU list\n");
				return -EINVAL;
			}
			break;

		case 'K':
			if (nb_k) {
				ERR("Only one of -k or -K can be specified\n");
				return -EINVAL;
			}

			if (parse_cpu_wq_param(cpu_idx, &nb_K, optarg)) {
				ERR("Failed to parse CPU to WQ map\n");
				return -EINVAL;
			}
			break;

		case 'l':
			tc->pg_size = strtoul(optarg, NULL, 0);
			if (tc->pg_size > 2) {
				ERR("large page size not supported %u\n",
					tc->pg_size);
				return -EINVAL;
			}
			tc->pg_size += 1;
			break;

		case 'm':
			tc->dma = 0;
			break;

		case 'n':
			tc->nb_bufs = strtoul(optarg, NULL, 0);
			break;

		case 'o':
			op = tc->op = strtoul(optarg, NULL, 0);
			if ((op >= (ARRAY_SIZE(op_info))) || !op_info[op].valid) {
				ERR("Invalid op %lu\n", op);
				return -EINVAL;
			}
			break;

		case 'O':
			sscanf(optarg, "%hu,%hu,%hu", &tc->buf_off[0], &tc->buf_off[1],
				&tc->buf_off[2]);
			for (i = 0; i < ARRAY_SIZE(tc->buf_off); i++)
				tc->buf_off[i] %= 4 * 1024;

			break;

		case 'P':
			tc->proc = 1;
			break;

		case 'q':
			tc->qd = strtoul(optarg, NULL, 0);
			break;

		case 's':
			if (parse_blen(&tc->blen, optarg) != 0)
				return -EINVAL;
			break;

		case 'S':
			n = tc->nb_numa_node;
			tc->numa_node = realloc(tc->numa_node,
						sizeof(tc->numa_node[0]) * (n + 1));
			if (tc->numa_node == NULL) {
				ERR("Failed to allocate memory for tc->numa_node\n");
				return -ENOMEM;
			}
			pi->nb_node = realloc(pi->nb_node,
					sizeof(pi->nb_node[0]) * (n + 1));
			if (pi->nb_node == NULL) {
				ERR("Failed to allocate memory for tc->nb_node\n");
				return -EINVAL;
			}
			init_tc_numa_node(&tc->numa_node[n]);
			pi->nb_node[n] = parse_numa_node(tc->numa_node[n], optarg);
			if (pi->nb_node[n] == 0 || pi->nb_node[n] == EOF) {
				free(pi->nb_node);
				return -EINVAL;
			}
			tc->nb_numa_node = n + 1;

			break;

		case 't':
			if (parse_blen(&tc->bstride, optarg) != 0)
				return -EINVAL;
			break;

		case 'T':
			tc->tval_secs = strtoul(optarg, NULL, 0);
			break;

		case 'W':
			printf("Warmup iteration - W, parameter deprecated, supply large i (e.g., 1000)\n");
			break;

		case 'w':
			tc->wq_type = strtoul(optarg, NULL, 0);
			if (tc->wq_type > 1) {
				ERR("Unsupported WQ type %u\n",
					tc->wq_type);
				return -EINVAL;
			}
			break;

		case 'u':
			tc->driver = USER;
			tc->nb_user_eng = optarg ? strtoul(optarg, NULL, 0) : -1;
			break;

		case 'v':
			tc->verify = strtoul(optarg, NULL, 10);
			break;

		case 'x':
			tc->misc_flags |= strtoul(optarg, NULL, 16);
			if (tc->misc_flags & DEVTLB_INIT_FLAG)
				printf("-x1 deprecated, use -n2 -q1 -t max(page size, align_h(buffer size, page size))\n");
			break;

		case 'Y':
			tc->drain_desc = 1;
			break;

		case 'y':
			nb_a = sscanf(optarg, "%c,%c,%c", &a[0], &a[1], &a[2]);
			if (nb_a == 0)
				return -EINVAL;
			for (i = 0; i < nb_a; i++) {
				a[i] = toupper(a[i]);

				if (access_map[ARR_IDX(toupper(a[i]))] == 0) {
					ERR("Unrecognized access %c\n", a[i]);
					return -EINVAL;
				}
			}
			pi->nb_a = nb_a;
			break;

		case 'z':
			nb_p = sscanf(optarg, "%c,%c,%c", &p[0], &p[1], &p[2]);
			if (nb_p == 0)
				return -EINVAL;
			for (i = 0; i < nb_p; i++) {
				p[i] = toupper(p[i]);

				if (place_map[ARR_IDX(toupper(p[i]))] == 0) {
					ERR("Unrecognized placement %c\n", p[i]);
					return -EINVAL;
				}
			}
			pi->nb_p = nb_p;
			break;

		case '?':
			return -EINVAL;

		default:
			break;
		}
	}

	tc->nb_cpus = nb_k ? nb_k : nb_K;

	return 0;
}

static int
parse_options(int argc, char **argv, struct tcfg *tc, struct parse_info *pi)
{
	int rc;
	unsigned int i;
	struct cpu_wq_info *cpu_idx;

	cpu_idx = calloc(get_nprocs(), sizeof(cpu_idx[0]));
	if (cpu_idx == NULL) {
		ERR("Failed to allocate cpu array\n");
		return -ENOMEM;
	}

	rc = do_getopt(argc, argv, tc, pi, cpu_idx);
	if (rc) {
		free(cpu_idx);
		return rc;
	}

	if (tc->nb_cpus == 0) {
		const char *cpu_str = "00000000";
		char *temp = strdup(cpu_str);

		if (!temp) {
			free(cpu_idx);
			return -ENOMEM;
		};

		snprintf(temp, sizeof(cpu_str), "%d", cpu_idx[0].c);
		parse_cpu_param(cpu_idx, &tc->nb_cpus, temp);
		free(temp);
	}

	tc->tcpu = mmap(NULL, tc->nb_cpus * sizeof(*tc->tcpu),
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (tc->tcpu == MAP_FAILED) {
		free(cpu_idx);
		ERR("Failed t allocate per cpu array\n");
		return -ENOMEM;
	}

	rc = test_barrier_init(tc);
	if (rc) {
		free(cpu_idx);
		return rc;
	}

	for (i = 0; i < tc->nb_cpus; i++) {
		tc->tcpu[i].cpu_num = cpu_idx[i].c;
		tc->tcpu[i].dname = cpu_idx[i].d;
		tc->tcpu[i].wq_id = cpu_idx[i].q;
		tc->tcpu[i].tcfg = tc;
	}

	for (i = 0; i < ARRAY_SIZE(op_info[tc->op].b_off); i++)
		if (op_info[tc->op].b_off[i])
			op_info[tc->op].nb_buf++;

	if (tc->bstride < tc->blen)
		tc->bstride = tc->blen;

	fixup_options(tc, pi);

	for (i = 0; i < op_info[tc->op].nb_buf ; i++) {
		tc->blen_arr[i] = tc->blen;
		tc->bstride_arr[i] = tc->bstride;

		if (pi->nb_p)
			tc->place_op[i] = place_map[ARR_IDX(toupper(pi->p[i]))];

		if (pi->nb_a)
			tc->access_op[i] = access_map[ARR_IDX(toupper(pi->a[i]))];

		if (tc->place_op[i] != OP_NONE && tc->access_op[i] == OP_NONE) {
			ERR("Place op specified(%c) but access_op is none\n",
				toupper(pi->p[i]));
			free(cpu_idx);
			return -EINVAL;
		}
	}

	for (; i < ARRAY_SIZE(tc->place_op); i++) {
		tc->place_op[i] = -1;
		tc->access_op[i] = -1;
	}

	switch (tc->op) {

	case DSA_OPCODE_CR_DELTA:
		/*
		 * The application doesn't know in advance the size of the delta record
		 * we model an application that uses the maximum delta size
		 */
		tc->delta_rec_size = (tc->blen / 8) * 10;
		tc->blen_arr[2] = tc->delta_rec_size;
		tc->bstride_arr[2] = tc->delta_rec_size;
		break;

	case DSA_OPCODE_AP_DELTA:
		tc->delta_rec_size = calc_delta_rec_size(tc);
		tc->bstride_arr[0] = tc->delta_rec_size;
		break;
	}

	tc->op_info = &op_info[tc->op];

	free(cpu_idx);

	return 0;
}

static int
validate_offsets(struct tcfg *tc)
{
	int rc;
	int i;

	switch (tc->op) {
		case DSA_OPCODE_DUALCAST:
			rc = tc->buf_off[1] != tc->buf_off[2] ? -EINVAL : 0;
			if (rc)
				ERR("Unequal Offset1 (%hd) & Offset2 (%hd)\n", tc->buf_off[1],
				tc->buf_off[2]);
			break;

		case DSA_OPCODE_CR_DELTA:
			for (i = 0; i < 2; i++) {
				rc = tc->buf_off[i] & 0x7 ? -EINVAL : 0;
				if (rc) {
					ERR("Non-8B alignment %d: (0x%hx)\n", i, tc->buf_off[i]);
					break;
				}
			}
			break;

		case DSA_OPCODE_AP_DELTA:
			rc = tc->buf_off[1] & 0x7 ? -EINVAL : 0;
			if (rc)
				ERR("Non-8B alignment %d: (0x%hx)\n", 1, tc->buf_off[1]);
			break;

		default:
			rc = 0;
			break;
	}

	return rc;
}

static int
validate_options(struct tcfg *tc, struct parse_info *pi)
{
	int i;
	int op = tc->op;
	int rc;

	/* DIF computation blocks */
	static const uint16_t bl_tbl[] = { 512, 520, 4096, 4104 };


	if (tc->nb_bufs == 0) {
		ERR("Buffer count invalid %d\n", tc->nb_bufs);
		return -EINVAL;
	}

	if (tc->blen > MAX_TRANSFER_SIZE) {
		ERR("Buffer size (%lu) exceeds max transfer size %u\n",
			tc->blen, MAX_TRANSFER_SIZE);
		return -EINVAL;
	}

	rc = validate_offsets(tc);
	if (rc)
		return rc;

	if (op == DSA_OPCODE_CR_DELTA && tc->blen % 8 != 0) {
		ERR("cr delta needs len to be 8 byte aligned\n");
		return -EINVAL;
	}

	if (op >= DSA_OPCODE_DIF_CHECK && op <= DSA_OPCODE_DIF_UPDT) {
		if (tc->bl_idx >= 4) {
			ERR("Invalid bl, should be [0-3]\n");
			return -EINVAL;
		}

		if (tc->blen % bl_tbl[tc->bl_idx] != 0) {
			ERR("buffer size is not multiple of block len\n");
			return -EINVAL;
		}

		tc->bl_len = bl_tbl[tc->bl_idx];
		update_dif_length(tc);
	}

	if (pi->nb_p && pi->nb_p < op_info[op].nb_buf) {
		ERR("Expected %d placement specifiers got %d for op %d\n",
			op_info[op].nb_buf, pi->nb_p, op);
		return -EINVAL;
	}

	for (i = 0; i < tc->nb_numa_node; i++) {
		if (pi->nb_node[i] && pi->nb_node[i] < op_info[op].nb_buf) {
			ERR("Expected %d numa node specifiers got %d for op %d\n",
				op_info[op].nb_buf, pi->nb_node[i], op);
			return -EINVAL;
		}
	}

	if (pi->nb_a && pi->nb_a < op_info[op].nb_buf) {
		ERR("Expected %d access specifiers got %d for op %d\n",
			op_info[op].nb_buf, pi->nb_a, op);
		return -EINVAL;
	}

	if (tc->dma && op_info[op].max_transfer_size
		 && tc->blen > op_info[op].max_transfer_size) {
		ERR("Max size of buffer is %x blen %lx\n",
				op_info[op].max_transfer_size, tc->blen);
		return -EINVAL;
	}

	return 0;
}

int do_options(int argc, char **argv, struct tcfg *tc)
{
	int rc;
	struct parse_info pi = {0};

	rc = parse_options(argc, argv, tc, &pi);
	if (rc)
		goto err_ret;

	rc = validate_options(tc, &pi);
	if (rc)
		goto err_ret;

	free(pi.nb_node);

	tc->op_info = &op_info[tc->op];

	return 0;

 err_ret:
	free(pi.nb_node);
	return rc;
}
