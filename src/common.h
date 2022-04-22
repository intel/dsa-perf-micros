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

#include "log.h"

#define TEST_CHAR	0x55
#define ALIGN(l) (((l) + 0xfff) & ~(0xfff))
#define ARRAY_SIZE(x) (sizeof((x))/sizeof((x)[0]))
#define MAX_COMP_RETRY	2000000000

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
	int retry;
	int mwait;
	int monitor;
	int os_dline_exp;
};

struct iter_stat {
	union {
		uint64_t stat[2];
		struct {
			uint64_t iter;
			uint64_t retry;
		};
	};
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
	int s;			/* num submissions */
	int qd;

	uint32_t cpu_num;	/* cpu number */
	union {
		pthread_t thread;
		unsigned long pid;
	};
	int mmap_fd;
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

	int monitor_cnt_arr[2]; /*
				 * 0 -> 0 monitor count (retry == 0)
				 * 1 -> completion detected between monitor & mwait
				 */

	int mwait_cnt_arr[3]; /*
			       * 0 -> Cnt of 0 mwaits
			       * 1 -> Cnt of 1 mwaits
			       * 2 -> Cnt of mwaits > 1
			       */
	struct wq_info *wq_info;
	int os_dline_exp;
	uint64_t min_cyc;
	uint64_t max_cyc;

	int numa_node;
	int numa_alloc_id;

	uint64_t drain_submitted;
	uint64_t drain_total_cycles;
	uint64_t nb_drain_completed;

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
	int id;
};

struct thread_data {
	pthread_mutex_t mutex;
	pthread_cond_t cv;
	pthread_mutexattr_t mutex_attr;
	pthread_condattr_t cv_attr;
	uint32_t barrier_cnt;
	bool err;
};

/*
 • This structure contains test parameters and controls for a given
 • invocation of the tool, and common across all executing threads.
 * Thread-specific parameters should go into struct tcfg_cpu.
 */
struct tcfg {
	uint64_t blen;		/* buffer size */
	uint64_t blen_arr[NUM_ADDR_MAX];
	uint64_t bstride;	/* buffer stride */
	uint64_t bstride_arr[NUM_ADDR_MAX];
	uint32_t nb_bufs;	/* buffer count */
	int qd;			/* queue depth */
	uint32_t nb_cpus;	/* cpu count for test */
	uint32_t pg_size;	/* 0 - 4K, 1 - 2Mb, 2 - 1G */
	uint32_t wq_type;	/* wq type */
	uint32_t batch_sz;	/* batch size */
	uint32_t iter;		/* iterations */
	uint32_t warmup_iter;	/* number of iterations used to warm up system state
				 * will not be included in measurements
				 */
	uint32_t op;		/* opcode */
	uint64_t cycles;	/* avg of execution cycles across CPUs */
	uint64_t retry;
	bool verify;		/* verify data after test  */
	bool dma;		/* use dma */
	bool var_mmio;		/* portal mmio address is varied */
	uint8_t bl_idx;
	uint16_t bl_len;	/* block length for DIF ops */
	int delta;		/* reciprocal of delta fraction */
	int tval_secs;
	uint32_t delta_rec_size;
	int numa_node_default[NUM_ADDR_MAX];
	int (*numa_node)[NUM_ADDR_MAX];
	int nb_numa_node_id;
	int access_op[NUM_ADDR_MAX];
	int place_op[NUM_ADDR_MAX];
	bool loop;		/* use descriptor loop */
	union {
		uint64_t fill;
		uint64_t pat;
	};
	struct thread_data *td;
	struct tcfg_cpu *tcpu;
	uint32_t misc_flags;
	uint16_t desc_flags;
	uint32_t ccmask;	/* cache control mask */
	uint32_t flags_cmask;	/* flags to clear in the descriptor */
	uint32_t flags_smask;	/* flags to set in the descriptor */
	uint32_t flags_nth_desc;/* flags to set at every "flags_nth_desc"th descriptor in a batch */

	int nb_desc;
	int driver;

	int vfio_fd;
	int nb_user_eng;

	struct op_info *op_info;
	uint64_t retries_per_sec;
	uint64_t cycles_per_sec;
	float cpu_util;
	int ops_rate;
	float latency;
	float bw;
	int proc;

	struct numa_mem *numa_mem;
	int nb_numa_node;

	void * (*malloc)(size_t size, unsigned int align, int numa_node);

	int drain_desc;
	uint64_t drain_lat;

	bool cpu_desc_work;
};

extern struct log_ctx log_ctx;

void init_buffers(struct tcfg_cpu *tcpu);

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

static inline int
comp_rec_size(struct tcfg_cpu *tcpu)
{
	if (!tcpu->wq_info)
		return 0;

	return tcpu->wq_info->dev_type == DSA ? 32 : 64;
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
			uint64_t delay;

			delay = __rdtsc() + UMWAIT_DELAY;
			poll_cnt->os_dline_exp += umwait(delay, UMWAIT_STATE);
			poll_cnt->mwait++;
		}
		poll_cnt->monitor++;
	}

}

static __always_inline int
poll_comp_common(struct dsa_completion_record *comp,
		struct poll_cnt  *poll_cnt, uint64_t flags)
{
	struct poll_cnt lcnt = { 0 };

	while (comp->status == 0 && lcnt.retry < MAX_COMP_RETRY) {
		do_comp_flags(comp, flags, &lcnt);
		lcnt.retry++;
	}

	if (lcnt.retry > MAX_COMP_RETRY)
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
	uint64_t align_sz;

	align_sz = len;

	align_sz = (align_sz + pg_sz_arr[pg_size] - 1) & ~(pg_sz_arr[pg_size] - 1);

	return align_sz;
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

#endif
