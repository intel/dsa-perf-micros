// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/memfd.h>
#include <linux/mempolicy.h>
#include <stdint.h>
#include <linux/idxd.h>
#include <errno.h>

#include "common.h"
#include "device.h"
#include "util.h"
#include "init.h"

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#endif
#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)
#endif

static inline
int set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode)
{
	return syscall(__NR_set_mempolicy, mode, nodemask, maxnode);
}


static off_t
file_sz(int fd)
{
	return lseek(fd, 0, SEEK_END);
}


#define PTR(p) ((void *)(uintptr_t)(p))

static struct numa_mem *
numa_mem_ptr(struct tcfg *tcfg, int numa_node)
{
	int i;

	for (i = 0; i < tcfg->nb_numa_node; i++)
		if (numa_node == tcfg->numa_mem[i].id)
			break;

	return &tcfg->numa_mem[i];
}

static uint64_t
numa_base_addr(struct tcfg *tcfg, int node)
{
	return (uint64_t)numa_mem_ptr(tcfg, node)->base_addr;
}

static void*
alloc_offset(uint64_t sz, uint64_t *ptotal)
{
	void *p = (void *)(*ptotal);

	*ptotal += sz;
	*ptotal += 0xfff;
	*ptotal &= ~0xfffUL;

	return p;
}

static void*
alloc_numa_offset(struct tcfg *tcfg, uint64_t sz, int numa_node)
{
	return alloc_offset(sz, &numa_mem_ptr(tcfg, numa_node)->sz);
}

static void
alloc_buf_offsets(struct tcfg *tcfg)
{
	int i, j;

	INFO("Offsets\n");
	for (i = 0; i < tcfg->nb_cpus; i++) {
		int node = tcfg->tcpu[i].numa_node;
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];
		uint64_t misc_b1_sz = tcfg->misc_flags & DEVTLB_INIT_FLAG ? tcfg->blen : 0;
		uint64_t misc_b2_sz = misc_b1_sz + comp_rec_size(tcpu);
		int numa_alloc_id = tcpu->numa_alloc_id;

		INFO("CPU %d Node %d\n", tcpu->cpu_num, tcpu->numa_node);
		if (tcfg->dma) {
			tcpu->desc = alloc_numa_offset(tcfg,
					tcfg->nb_bufs * sizeof(tcpu->desc[0]), node);
			if (tcfg->batch_sz > 1)
				tcpu->bdesc = alloc_numa_offset(tcfg,
					tcfg->nb_desc * sizeof(tcpu->bdesc[0]), node);

			/* *2 for IAX completion desc size */
			tcpu->comp = alloc_numa_offset(tcfg,
					tcfg->nb_bufs * sizeof(tcpu->comp[0]) *  2, node);
			if (tcfg->batch_sz > 1)
				tcpu->bcomp = alloc_numa_offset(tcfg,
					tcfg->nb_desc * sizeof(tcpu->bcomp[0]), node);
			INFO("comp %p bcomp %p desc %p bdesc %p\n",
				tcpu->comp, tcpu->bcomp, tcpu->desc, tcpu->bdesc);
		}

		for (j = 0; j < tcfg->op_info->nb_buf; j++) {
			uint64_t sz = tcfg->bstride_arr[j] * tcfg->nb_bufs;
			int n = tcfg->numa_node[numa_alloc_id][j] == -1 ? tcpu->numa_node :
							tcfg->numa_node[numa_alloc_id][j];

			tcpu->b[j] = alloc_numa_offset(tcfg, sz, n);
			INFO("Buf %d Node %d offset %p\n", j, n, tcpu->b[j]);
		}

		if (misc_b1_sz == 0)
			continue;

		node = tcfg->tcpu[i].numa_node;
		tcpu->misc_b1 = alloc_numa_offset(tcfg, misc_b1_sz, node);
		tcpu->misc_b2 = alloc_numa_offset(tcfg, misc_b2_sz, node);

		INFO("misc_b1 %p misc_b2 %p\n", tcpu->misc_b1, tcpu->misc_b2);
	}
}

#define PTR_ADD(p, a) { p = (void *)((uintptr_t)(p) + (uintptr_t)a); }

static int
alloc_node_mem(struct tcfg *tcfg, uint64_t sz, int n, void **paddr)
{
	uint32_t huge_flags[] = {0, MFD_HUGETLB | MFD_HUGE_2MB, MFD_HUGETLB | MFD_HUGE_1GB};
	uint64_t node_mask;
	int fd;
	int rc;

	if (sz == 0) {
		*paddr = 0;
		return 0;
	}

	if (tcfg->malloc) {
		*paddr = tcfg->malloc(sz, 4096, n);
		return *paddr == NULL ? -ENOMEM : 0;
	}

	fd = memfd_create("temp", huge_flags[tcfg->pg_size]);
	if (fd < 0) {
		rc = -errno;
		ERR("Error creating memfd failed: %s\n", strerror(errno));
		return rc;
	}

	rc = ftruncate(fd, page_align_sz(tcfg, sz));
	if (rc < 0) {
		rc = -errno;
		ERR("Error in ftruncate: %s\n", strerror(errno));
		return rc;
	}

	node_mask = 1ULL << n;
	rc = set_mempolicy(MPOL_BIND, &node_mask, 64);
	if (rc) {
		rc = -errno;
		ERR("failed to bind memory range %s\n", strerror(errno));
		return rc;
	}

	*paddr = mmap(NULL, file_sz(fd), PROT_READ | PROT_WRITE,
		MAP_POPULATE | MAP_SHARED, fd, 0);
	close(fd);
	rc = set_mempolicy(MPOL_DEFAULT, NULL, 64);
	if (rc || *paddr == MAP_FAILED) {
		rc = -errno;
		if (*paddr != MAP_FAILED)
			munmap(*paddr, file_sz(fd));
		else
			ERR("Failed to mmap %lu from node %d\n",
				page_align_sz(tcfg, sz), n);
		return rc;
	}

	return 0;
}

static int
alloc_numa_mem(struct tcfg *tcfg)
{
	int rc;
	int i;

	for (i = 0; i < tcfg->nb_numa_node; i++) {
		void *addr;
		struct numa_mem *nm = &tcfg->numa_mem[i];

		addr = NULL;
		rc = alloc_node_mem(tcfg, nm->sz, nm->id, &addr);
		if (rc)
			return rc;
		INFO("Node %d: %p size 0x%016lx\n", nm->id, addr, nm->sz);
		nm->base_addr = addr;
	}

	return 0;
}

static void
add_base_addr(struct tcfg *tcfg)
{
	int i;

	for (i = 0; i < tcfg->nb_cpus; i++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];
		int n = tcpu->numa_node;
		uint64_t ba = numa_base_addr(tcfg, n);
		int j;

		if (tcfg->dma) {
			if (tcfg->batch_sz > 1) {
				PTR_ADD(tcpu->bdesc, ba);
				PTR_ADD(tcpu->bcomp, ba);
			}

			PTR_ADD(tcpu->desc, ba);
			PTR_ADD(tcpu->comp, ba);
		}

		PTR_ADD(tcpu->misc_b1, ba);
		PTR_ADD(tcpu->misc_b2, ba);

		for (j = 0; j < tcfg->op_info->nb_buf; j++) {
			uint32_t off = tcfg->op_info->b_off[j];
			char **pb = (char **)((char *)tcpu + off);
			int numa_alloc_id = tcpu->numa_alloc_id;

			n = tcfg->numa_node[numa_alloc_id][j] == -1 ? tcpu->numa_node :
							tcfg->numa_node[numa_alloc_id][j];
			PTR_ADD(tcpu->b[j], numa_base_addr(tcfg, n));
			*pb = tcpu->b[j];
		}

	}

	if (tcfg->pg_size != 0)
		return;
}

static int
test_init_mem(struct tcfg *tcfg)
{
	int rc;

	alloc_buf_offsets(tcfg);
	rc = alloc_numa_mem(tcfg);
	if (rc)
		return rc;

	add_base_addr(tcfg);

	return 0;
}

static int
test_init_wq(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;

	if (!tcfg->dma)
		return 0;

	tcpu->wq_info = malloc(sizeof(*tcpu->wq_info));
	if (!tcpu->wq_info) {
		ERR("Failed to allocate memory for wq info\n");
		return -ENOMEM;
	}

	tcpu->wq = wq_map(tcpu->dname, tcpu->wq_id, tcfg->wq_type == 1,
			node_id());
	if (tcpu->wq == NULL) {
		ERR("Failed to map WQ\n");
		free(tcpu->wq_info);
		tcpu->wq_info = NULL;
		return -ENOMEM;
	}

	wq_info_get(tcpu->wq, tcpu->wq_info);
	tcpu->dwq = tcpu->wq_info->dwq;
	tcpu->qd = (!tcpu->dwq || tcfg->qd == 0 || !tcfg->loop) ?
				tcpu->wq_info->size : tcfg->qd;
	tcpu->qd = min(tcpu->qd, tcfg->nb_desc);

	INFO("CPU %d dname %s wq size %d shared %d qd %d\n", tcpu->cpu_num,
		tcpu->wq_info->dname, tcpu->wq_info->size, !tcpu->wq_info->dwq,
		tcpu->qd);
	return 0;
}

static int
test_init_dmap(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	int err;
	int fd;
	int i;

	if (!tcfg->dma)
		return 0;

	fd = tcpu->wq_info->dmap_fd;
	tcpu->err = dmap(fd, tcpu->desc, ALIGN(tcfg->nb_bufs * sizeof(tcpu->desc[0])));
	if (tcpu->err)
		return tcpu->err;

	if (tcfg->batch_sz > 1) {
		tcpu->err = dmap(fd, tcpu->bdesc, ALIGN(tcfg->nb_desc * sizeof(tcpu->bdesc[0])));
		if (tcpu->err) {
			err = tcpu->err;
			goto unmap_desc;
		}
	}

	tcpu->err = dmap(fd, tcpu->comp, ALIGN(tcfg->nb_bufs * sizeof(tcpu->comp[0]) * 2));
	if (tcpu->err) {
		err = tcpu->err;
		goto unmap_bdesc;
	}

	if (tcfg->batch_sz > 1) {
		tcpu->err = dmap(fd, tcpu->bcomp, ALIGN(tcfg->nb_desc * sizeof(tcpu->bcomp[0])));
		if (tcpu->err) {
			err = tcpu->err;
			goto unmap_comp;
		}
	}

	for (i = 0; i < tcfg->op_info->nb_buf; i++) {
		uint64_t sz = tcfg->bstride_arr[i] * tcfg->nb_bufs;

		tcpu->err = dmap(fd, tcpu->b[i], ALIGN(sz));
		if (tcpu->err) {
			err = tcpu->err;
			goto unmap_buf;
		}
	}

	return 0;

 unmap_buf:
	for (i = i - 1; i >= 0; i--) {
		uint64_t sz = tcfg->bstride_arr[i] * tcfg->nb_bufs;

		dunmap(fd, tcpu->b[i], ALIGN(sz));
	}

	if (tcfg->batch_sz > 1)
		dmap(fd, tcpu->bcomp, ALIGN(tcfg->nb_desc * sizeof(tcpu->bcomp[0])));

 unmap_comp:
	dunmap(fd, tcpu->comp, ALIGN(tcfg->nb_bufs * sizeof(tcpu->comp[0]) * 2));

 unmap_bdesc:
	if (tcfg->batch_sz > 1)
		dunmap(fd, tcpu->bdesc, ALIGN(tcfg->nb_desc * sizeof(tcpu->bdesc[0])));
 unmap_desc:
	dunmap(fd, tcpu->desc, ALIGN(tcfg->nb_bufs * sizeof(tcpu->desc[0])));

	return err;
}

void
test_init_percpu(struct tcfg_cpu *tcpu)
{

	tcpu->err = test_init_wq(tcpu);
	if (tcpu->err)
		return;

	tcpu->err = test_init_dmap(tcpu);
}

void
dunmap_per_cpu(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	int fd;
	int i;

	if (!tcfg->dma || !tcpu->wq_info)
		return;

	fd = tcpu->wq_info->dmap_fd;

	dunmap(fd, tcpu->desc, ALIGN(tcfg->nb_bufs * sizeof(tcpu->desc[0])));

	if (tcfg->batch_sz > 1)
		dunmap(fd, tcpu->bdesc, ALIGN(tcfg->nb_desc * sizeof(tcpu->bdesc[0])));

	dunmap(fd, tcpu->comp, ALIGN(tcfg->nb_bufs * sizeof(tcpu->comp[0]) * 2));
	dunmap(fd, tcpu->bcomp, ALIGN(tcfg->nb_desc * sizeof(tcpu->bcomp[0])));

	for (i = 0; i < tcfg->op_info->nb_buf; i++) {
		uint64_t sz = tcfg->bstride_arr[i] * tcfg->nb_bufs;

		dunmap(fd, tcpu->b[i], ALIGN(sz));
	}
}

void
test_free(struct tcfg *tcfg)
{
	unsigned int i;

	for (i = 0; i < tcfg->nb_numa_node; i++)
		munmap(tcfg->numa_mem[i].base_addr,
			page_align_sz(tcfg, tcfg->numa_mem[i].sz));

	if (tcfg->td) {
		pthread_mutexattr_destroy(&tcfg->td->mutex_attr);
		pthread_condattr_destroy(&tcfg->td->cv_attr);
		pthread_mutex_destroy(&tcfg->td->mutex);
		pthread_cond_destroy(&tcfg->td->cv);
	}

	if (tcfg->tcpu) {
		for (i = 0; i < tcfg->nb_cpus; i++)
			free(tcfg->tcpu[i].dname);
	}

	if (tcfg->td)
		munmap(tcfg->td, sizeof(struct thread_data));
	if (tcfg->tcpu)
		munmap(tcfg->tcpu, tcfg->nb_cpus*sizeof(*tcfg->tcpu));

	free(tcfg->numa_node);
	free(tcfg->numa_mem);
}

static inline uint64_t
get_ms(void)
{
	struct timeval tp;

	gettimeofday(&tp, NULL);

	return tp.tv_sec*1000+tp.tv_usec/1000;
}

static void
calibrate(uint64_t *cycles_per_sec)
{
	uint64_t  start;
	uint64_t  end;
	uint64_t starttick, endtick;
	uint64_t ms_diff, cycle_diff;

	endtick = get_ms();

	while (endtick == (starttick = get_ms()))
		;

	/* Measure cycle diff for 500 ms */
	start = rdtsc();
	while ((endtick = get_ms())  < (starttick + 500))
		;
	end = rdtsc();

	cycle_diff = end - start;
	ms_diff = endtick - starttick;

	/* ms * cycles_per_sec = cycle_diff * 1000 */

	*cycles_per_sec = (cycle_diff * (uint64_t)1000)/ms_diff;
}

static void
set_alarm_done(struct dsa_completion_record *comp)
{
	static struct dsa_completion_record *done;

	if (comp) {
		done = comp;
		comp->status = 0;
	} else
		done->status = DSA_COMP_SUCCESS;
}

static void
catch_alarm(int sig)
{
	set_alarm_done(NULL);
	signal(sig, SIG_DFL);
}

static void
calibrate_retries(uint64_t *retries_per_sec, uint32_t flags)
{
	struct dsa_completion_record comp;
	struct poll_cnt poll_cnt = {0};

	flags &= ~CPL_UMWAIT;
	set_alarm_done(&comp);

	signal(SIGALRM, catch_alarm);
	alarm(1);

	poll_comp_common(&comp, &poll_cnt, flags);
	*retries_per_sec = poll_cnt.retry;
}

static const char *const init_cmd[] = {
			"echo never > /sys/kernel/mm/transparent_hugepage/enabled",
			"echo 0 > /proc/sys/kernel/numa_balancing",
			"x86_energy_perf_policy performance",
			"cpupower frequency-set -g performance 1>/dev/null",
			"for x in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do "
			"[ -f $x ] && echo performance > $x 1>/dev/null; done"
			};

static int
system_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(init_cmd); i++)
		if (system(init_cmd[i]))
			ERR("i: %s failed\n", init_cmd[i]);
	return 0;
}

static int
calc_nb_desc(struct tcfg *tcfg)
{
	if (tcfg->batch_sz == 1)
		return tcfg->nb_bufs;

	return tcfg->nb_bufs/tcfg->batch_sz +
			!!(tcfg->nb_bufs % tcfg->batch_sz);
}


int
test_init_global(struct tcfg *tcfg)
{
	int err;
	int i, j;
	uint64_t node_mask, tmp_node_mask;
	int nb_node;

	err = system_init();
	if (err)
		return err;

	node_mask = 0;
	nb_node = 0;
	for (i = 0; i < tcfg->nb_cpus; i++) {
		int n;

		cpu_pin(tcfg->tcpu[i].cpu_num);
		n = node_id();
		tcfg->tcpu[i].numa_node = n;
		node_mask = node_mask | (1ULL << n);
	}

	INFO("CPU NUMA node mask 0x%016lx\n", node_mask);
	tmp_node_mask = node_mask;
	nb_node = __builtin_popcount(node_mask);

	if (tcfg->nb_numa_node_id == 0) {
		tcfg->numa_node = calloc(nb_node, sizeof(tcfg->numa_node[0]));
		if (!tcfg->numa_node)
			return -ENOMEM;

		for (i = 0; i < nb_node; i++)
			memmove(&tcfg->numa_node[i], tcfg->numa_node_default,
				sizeof(tcfg->numa_node[0]));
		tcfg->nb_numa_node_id = nb_node;
	}


	if (tcfg->nb_numa_node_id != nb_node) {
		ERR("Numa specifiers (%d) does not match numa node count (%d)\n",
			tcfg->nb_numa_node_id, nb_node);
		return -EINVAL;
	}

	for (i = 0; i < nb_node; i++) {
		int n = __builtin_ffs(tmp_node_mask) - 1;

		for (j = 0; j < tcfg->nb_cpus; j++) {
			if (tcfg->tcpu[j].numa_node == n)
				tcfg->tcpu[j].numa_alloc_id = i;
		}

		tmp_node_mask = tmp_node_mask & (~(1ULL << n));
	}

	for (j = 0; j < tcfg->nb_numa_node_id; j++) {
		for (i = 0; i < ARRAY_SIZE(tcfg->numa_node[0]); i++)
			if (tcfg->numa_node[j][i] != -1)
				node_mask |= (1ULL << tcfg->numa_node[j][i]);

	}

	nb_node = __builtin_popcount(node_mask);
	tcfg->nb_numa_node = nb_node;
	tcfg->numa_mem = calloc(nb_node, sizeof(tcfg->numa_mem[0]));
	if (!tcfg->numa_mem)
		return -ENOMEM;

	for (i = 0; i < nb_node; i++) {
		int n = __builtin_ffs(node_mask) - 1;

		tcfg->numa_mem[i].id = n;
		node_mask = node_mask & (~(1ULL << n));
	}

	calibrate(&tcfg->cycles_per_sec);

	tcfg->nb_desc = calc_nb_desc(tcfg);

	err = driver_init(tcfg);
	if (err)
		return err;

	err = test_init_mem(tcfg);
	if (err)
		return err;

	if (!tcfg->dma)
		return 0;

	calibrate_retries(&tcfg->retries_per_sec, tcfg->misc_flags);

	return 0;
}
