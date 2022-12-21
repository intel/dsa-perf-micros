// SPDX-License-Identifier: GPL-2.0
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <x86intrin.h>
#include <linux/idxd.h>
#include <linux/types.h>

#include "log.h"

#define TEST_CHAR	0x55
#define ALIGN(l)	(((l) + 0xfff) & ~(0xfff))
#define ARRAY_SIZE(x)	(sizeof((x))/sizeof((x)[0]))
#define MAX_COMP_RETRY	2000000000
#define PTR_ADD(p, a)	{ p = (void *)((uintptr_t)(p) + (uintptr_t)a); }
#define TIME_DELAY_SEC	4

/* max number of operands e.g., dual cast - src1, dst1, dst2 */
#define NUM_ADDR_MAX	3

enum {
	DSA = 0,
	IAX
};

enum {
	IDXD,
	USER
};

#define OP_NONE	1
enum {
	OP_FETCH = OP_NONE + 1,
	OP_DEMOTE,
	OP_FLUSH
};

enum {
	OP_READ = OP_NONE + 1,
	OP_WRITE
};

/* defines for misc_flags param */
enum {
	DEVTLB_INIT_FLAG = 1 << 0,
	CPL_PAUSE = 1 << 7,
	CPL_UMWAIT = 1 << 8,
	TEST_M64 = 1 << 27,
	TEST_DB = 1 << 28,
	TEST_M64MEM = 1 << 29,
	TEST_ENQ = 1 << 30,
	TEST_ENQMEM = 1 << 31
};


struct tcfg;

struct delta_rec {
	uint16_t off;
	uint64_t val;
} __attribute__((__packed__));


struct delta {
	struct delta_rec drec[64 * 1024];
};

struct wq_info {
	const char *dname;
	int dmap_fd;
	int size;
	int dwq;
	int dev_type;
};

struct poll_cnt {
	union {
		uint64_t retry;
		int monitor;
	};
	int mwait;
	uint64_t mwait_cycles;
};

struct iter_stat {
	union {
		uint64_t stat[3];
		struct {
			uint64_t iter;
			uint64_t retry;
			uint64_t mwait_cycles;
		};
	};
};

/*
 * T10 Protection Information tuple.
 */
struct t10_pi_tuple {
	__be16 guard_tag;	/* Checksum */
	__be16 app_tag;		/* Opaque storage */
	__be32 ref_tag;		/* Target LBA or indirect LBA */
};

/*
 • Structure containing test parameters unique to each thread of execution.
 * Parameters common to all threads should be placed in struct tcfg
 */
struct __attribute__ ((aligned (64))) tcfg_cpu {
	uint8_t addr_none[0];
	void *wq;
	int crdt;		/* wq credits */
	int dwq;
	int qd;

	uint32_t cpu_num;	/* cpu number */
	union {
		pthread_t thread;
		unsigned long pid;
	};
	char *dname;
	int wq_id;

	char *b[NUM_ADDR_MAX];

	char *src1, *src2;
	char *src, *dst, *dst1, *dst2;
	struct delta_rec *delta;

	char *misc_b1;
	char *misc_b2;

	uint64_t cycles;	/* CPU cycle count for test on this CPU */
	uint64_t tstart;
	uint64_t tend;
	struct iter_stat prev_stat;
	struct iter_stat curr_stat;
	int err;		/* err code after init or test execution */
	struct dsa_completion_record *comp;
	struct dsa_completion_record *bcomp;
	struct dsa_hw_desc *desc;
	struct dsa_hw_desc *bdesc;
	struct tcfg *tcfg;	/* pointer to test cfg */

	struct wq_info *wq_info;
	uint64_t min_cyc;
	uint64_t max_cyc;

	int numa_node;

	uint64_t drain_submitted;
	uint64_t drain_total_cycles;
	uint64_t nb_drain_completed;

	union {
		void *op_priv;
		uint32_t *crc;
		struct t10_pi_tuple *dif_tag;
	};
};

struct op_info {
	bool valid;
	unsigned int nb_buf;
	uint32_t max_transfer_size;
	uint32_t b_off[NUM_ADDR_MAX];	/*
					 * offsets of tcfg structure members(src/dst)
					 * that are set up to point to tcfg.b[]s
					 * of this op
					 */
	bool init_req;
};

struct numa_mem {
	void *base_addr;
	uint64_t sz;
};

struct mmio_mem {
	char *bfile;
	uint64_t mmio_offset;
	void *base_addr;
	uint64_t sz;
	int fd;
};

/*
 • This structure contains test parameters and controls for a given
 • invocation of the tool, and common across all executing threads.
 * Thread-specific parameters should go into struct tcfg_cpu.
 */
struct tcfg {
	uint64_t blen;				/* buffer size (-s) */
	uint64_t bstride;			/* buffer stride (-t) */
	uint32_t nb_bufs;			/* buffer count (-n) */
	int qd;					/* queue depth (-q) */
	uint32_t nb_cpus;			/* cpu count for test - parsed from -k/-K */
	uint32_t pg_size;			/* 0 - 4K, 1 - 2Mb, 2 - 1G (-l) */
	uint32_t wq_type;			/* wq type (-w) */
	uint32_t batch_sz;			/* batch size (-b) */
	uint32_t iter;				/* iterations (-i) */
	uint32_t op;				/* opcode (-o) */
	bool verify;				/* verify data after generating descriptors (-v)  */
	bool dma;				/* use dma v/s memcpy (-m) */
	bool var_mmio;				/* portal mmio address is varied (-c) */
	uint8_t bl_idx;				/* selects one of the 4 block lengths (-e) */
	uint16_t bl_len;			/* block length for DIF ops, derived from bl_idx */
	int delta;				/* reciprocal of delta fraction (-D) */
	uint32_t delta_rec_size;		/* derived from buffer size (-S) and -D options */
	int tval_secs;				/* -T */

	int numa_node_default[NUM_ADDR_MAX];	/* default NUMA allocation (-1, -1) */
	int (*numa_node)[NUM_ADDR_MAX];		/* NUMA allocation (-S) */

	int place_op[NUM_ADDR_MAX];		/* -y */
	int access_op[NUM_ADDR_MAX];		/* -z */
	uint16_t buf_off[NUM_ADDR_MAX];		/* -O */
	uint32_t misc_flags;			/* -x */
	uint32_t ccmask;			/* cache control mask (-f) */
	uint32_t flags_cmask;			/* flags to clear in the descriptor (-F) */
	uint32_t flags_smask;			/* flags to set in the descriptor (-F) */
	uint32_t flags_nth_desc;		/* flags to set at every "flags_nth_desc"th descriptor in a batch (-Y) */
	int proc;				/* uses processes not threads (-P) */
	int driver;				/* user driver(uio/vfio_pci) (-u) */
	int nb_user_eng;			/* number of engines to use with -u */
	int drain_desc;				/* drain desc (-Y) */
	bool shuffle_descs;			/* shuffle descriptors */

	uint64_t blen_arr[NUM_ADDR_MAX];
	uint64_t bstride_arr[NUM_ADDR_MAX];

	union {					/* fill/pattern value used for o4/o6 */
		uint64_t fill;
		uint64_t pat;
	};

	uint32_t nb_desc;			/* num descriptors not including batch */

	uint64_t bw_cycles;
	uint64_t cycles;			/* avg of execution cycles across CPUs */
	uint64_t retry;				/* completion polling retries */
	uint64_t mwait_cycles;			/* cycles spent in mwait */
	float cpu_util;				/* cpu utilization needed to prep/submit descriptors */
	int kops_rate;				/* operation rate - kilo operations/sec */
	float latency;				/* latency for n descriptors */
	float bw;				/* operation BW */
	uint64_t retries_per_sec;		/* pollling retries the CPU can do per sec  */
	uint64_t cycles_per_sec;		/* rdtsc cycles per sec */
	uint64_t drain_lat;			/* calculated drain latency per descriptor */

	struct thread_data *td;			/* barrier */
	struct tcfg_cpu *tcpu;			/* per worker data */

	struct numa_mem *numa_mem;		/* per memory node info */
	int nb_numa_node;			/* size of each of the numa_xyz arrays
						 * nb_numa_node is the index of the
						 * highest numa node id on the system
						 */
	int *numa_nb_cpu;			/* numa_nb_cpu[i] is the cpu count in node i */

	int vfio_fd;				/* VFIO filehandle (-u with vfio_pci) */

	struct op_info *op_info;


	void * (*malloc)(size_t size, unsigned int align, int numa_node);


	bool cpu_desc_work;

	int mmio_fd_idx[NUM_ADDR_MAX];		/* address index (0 - 2) into mmio_mem */
	struct mmio_mem mmio_mem[NUM_ADDR_MAX];	/* per mmio file info - mmio files maybe duplicated
						 * in that case, mmio_idx points to a single mmio_mem
						 * struct
						 */

	bool stop;
};

extern struct log_ctx log_ctx;

void init_buffers(struct tcfg_cpu *tcpu);

static inline bool
is_work_rate_sub_test(struct tcfg *tcfg)
{
	return tcfg->op == DSA_OPCODE_NOOP &&
		tcfg->misc_flags & (TEST_M64 | TEST_DB | TEST_M64MEM | TEST_ENQ | TEST_ENQMEM);
}

static inline void
cldemote(volatile void *p)
{
	asm volatile(".byte 0x0f, 0x1c, 0x07\t\n"
			:
			: "D" (p));
}

static inline
void clwb_asm(volatile void *__p)
{
	asm volatile("clwb %0" : "+m" (*(volatile char  *)__p));
}

static inline
void clflushopt(volatile void *__p)
{
	asm volatile("clflushopt %0" : "+m" (*(volatile char  *)__p));
}

static inline void
cflush(char *buf, uint64_t len)
{
	char *b = buf;
	char *e = buf + len;

	for (; b < e; b += 64)
		clflushopt(b);
}

static inline void
clwb(char *buf, uint64_t len)
{
	char *b = buf;
	char *e = buf + len;

	for (; b < e; b += 64)
		clwb_asm(b);
}

static inline uint64_t
align(uint64_t v, uint64_t alignto)
{
	return  (v + alignto - 1) & ~(alignto - 1);
}

#define CACHE_LINE_SIZE	64

static inline uint64_t
comp_rec_cache_aligned_size(struct tcfg_cpu *tcpu)
{
	uint64_t sz = tcpu->wq_info->dev_type == DSA ? sizeof(struct dsa_completion_record) :
						sizeof(struct iax_completion_record);
	if (!tcpu->wq_info)
		return 0;

	return align(sz, CACHE_LINE_SIZE);
}

static inline uint32_t
min(uint64_t a, uint64_t b)
{
	if (a < b)
		return a;

	return b;
}

static inline uint32_t
max(uint64_t a, uint64_t b)
{
	if (a > b)
		return a;

	return b;
}

static __always_inline uint64_t
rdtsc(void)
{
	uint64_t tsc;
	unsigned int dummy;

	/*
	 * https://www.felixcloutier.com/x86/rdtscp
	 * The RDTSCP instruction is not a serializing instruction, but it
	 * does wait until all previous instructions have executed and all
	 * previous loads are globally visible
	 *
	 * If software requires RDTSCP to be executed prior to execution of
	 * any subsequent instruction (including any memory accesses), it can
	 * execute LFENCE immediately after RDTSCP
	 */
	tsc = __rdtscp(&dummy);
	__builtin_ia32_lfence();

	return tsc;
}

static inline void
umonitor(volatile void *addr)
{
	asm volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xf0" : : "a"(addr));
}

static inline int
umwait(unsigned long timeout, unsigned int state)
{
	uint8_t r;
	uint32_t timeout_low = (uint32_t)timeout;
	uint32_t timeout_high = (uint32_t)(timeout >> 32);

	timeout_low = (uint32_t)timeout;
	timeout_high = (uint32_t)(timeout >> 32);

	asm volatile(".byte 0xf2, 0x48, 0x0f, 0xae, 0xf1\t\n"
		"setc %0\t\n"
		: "=r"(r)
		: "c"(state), "a"(timeout_low), "d"(timeout_high));
	return r;
}

#define UMWAIT_DELAY 100000
/* C0.1 state */
#define UMWAIT_STATE 1

static __always_inline void
do_comp_flags(struct dsa_completion_record *comp, uint32_t flags,
	struct poll_cnt *poll_cnt)
{
	if (flags & CPL_PAUSE) {
		__builtin_ia32_pause();
	} else if (flags & CPL_UMWAIT) {

		umonitor(comp);
		if (comp->status == 0) {
			uint64_t tsc = __rdtsc();
			uint64_t delay;

			delay = tsc + UMWAIT_DELAY;
			umwait(delay, UMWAIT_STATE);
			poll_cnt->mwait_cycles += __rdtsc() - tsc;
		}
	}
}

static __always_inline int
poll_comp_common(struct dsa_completion_record *comp,
		struct poll_cnt  *poll_cnt, uint64_t flags, uint64_t max_retry)
{
	struct poll_cnt lcnt = { 0 };

	while (comp->status == 0 && lcnt.retry++ < max_retry)
		do_comp_flags(comp, flags, &lcnt);

	if (lcnt.retry > max_retry)
		ERR("timed out\n");

	if (poll_cnt)
		*poll_cnt = lcnt;

	return !(comp->status == DSA_COMP_SUCCESS);
}

static inline uint64_t
page_align_sz(struct tcfg *tcfg, uint64_t len)
{
	static const uint64_t pg_sz_arr[] = {4*1024, 2 * 1024 * 1024, 1024 * 1024 * 1024};
	int pg_size = tcfg->pg_size;

	return align(len, pg_sz_arr[pg_size]);
}

static inline struct dsa_hw_desc *
desc_ptr(struct tcfg_cpu *tcpu)
{
	return tcpu->tcfg->batch_sz == 1 ? tcpu->desc :
						tcpu->bdesc;
}

#ifndef __NR_getcpu
#define __NR_getcpu	309
#endif

static inline unsigned int
node_id(void)
{
	unsigned int n;

	syscall(__NR_getcpu, NULL, &n, NULL);

	return n;
}

static inline uint64_t
data_size_per_iter(struct tcfg *tcfg)
{
	uint64_t sz;
	struct delta_rec dc;

	switch (tcfg->op) {
	case DSA_OPCODE_NOOP:
		sz = 64;
		break;

	case DSA_OPCODE_AP_DELTA:
		/*
		 * AP delta (may) write 8 byte partials, in which case it will limit op BW,
		 * hence we measure AP Delta write BW
		 */
		sz = (tcfg->delta_rec_size/sizeof(dc)) * sizeof(dc.val);
		break;

	default:
		sz = tcfg->blen;
		break;
	}

	return sz * tcfg->nb_cpus * tcfg->nb_bufs;
}

static inline void
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

#endif
