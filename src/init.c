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
#include <numa.h>
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
	return numa_node < tcfg->nb_numa_node ?
			&tcfg->numa_mem[numa_node] :
			NULL;
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

static int
buffer_id_to_node(struct tcfg_cpu *tcpu, int bid)
{
	struct tcfg *tcfg = tcpu->tcfg;
	int n = tcpu->numa_node;

	return tcfg->numa_node[n][bid] == -1 ?
		n : tcfg->numa_node[n][bid];
}

static void*
alloc_numa_offset(struct tcfg *tcfg, uint64_t sz, int numa_node, uint32_t off)
{
	numa_mem_ptr(tcfg, numa_node)->sz += off;

	return alloc_offset(sz, &numa_mem_ptr(tcfg, numa_node)->sz);
}

static void*
alloc_mmio_offset(struct tcfg *tcfg, uint64_t sz, int bid, uint32_t off)
{
	int fd = tcfg->mmio_fd_idx[bid];

	tcfg->mmio_mem[fd].sz += off;

	return alloc_offset(sz, &tcfg->mmio_mem[fd].sz);
}

static void
alloc_buf_offsets(struct tcfg *tcfg)
{
	int i, j;
	size_t cs = sizeof(struct iax_completion_record);

	if (cs < sizeof(struct dsa_completion_record))
		cs = sizeof(struct dsa_completion_record);

	cs = align(cs, CACHE_LINE_SIZE);

	INFO("Offsets\n");
	for (i = 0; i < tcfg->nb_cpus; i++) {
		int node = tcfg->tcpu[i].numa_node;
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

		INFO("CPU %d Node %d\n", tcpu->cpu_num, tcpu->numa_node);
		if (tcfg->dma) {
			tcpu->desc = alloc_numa_offset(tcfg,
					tcfg->nb_bufs * sizeof(tcpu->desc[0]), node, 0);
			if (tcfg->batch_sz > 1)
				tcpu->bdesc = alloc_numa_offset(tcfg,
					tcfg->nb_desc * sizeof(tcpu->bdesc[0]), node, 0);

			/*
			 * We allocate completion records on cacheline boundaries for
			 * better performance
			 */
			tcpu->comp = alloc_numa_offset(tcfg, tcfg->nb_bufs * cs,
						node, 0);

			if (tcfg->batch_sz > 1)
				tcpu->bcomp = alloc_numa_offset(tcfg,
								tcfg->nb_desc * cs,
								node, 0);
			INFO("comp %p bcomp %p desc %p bdesc %p\n",
				tcpu->comp, tcpu->bcomp, tcpu->desc, tcpu->bdesc);
		}
	}

	/*
	 * allocate for all b[0] followed by b[1] and so on, this logic
	 * uses the offsets in bdf:offset for -B (mmio)  correctly
	 */
	for (j = 0; j < tcfg->op_info->nb_buf; j++) {
		for (i = 0; i < tcfg->nb_cpus; i++) {
			struct tcfg_cpu *tcpu = &tcfg->tcpu[i];
			uint64_t sz = tcfg->bstride_arr[j] * tcfg->nb_bufs;

			if (tcfg->mmio_mem[j].bfile)
				tcpu->b[j] = alloc_mmio_offset(tcfg, sz, j, tcfg->buf_off[j]);
			else {
				int n = buffer_id_to_node(tcpu, j);
				tcpu->b[j] = alloc_numa_offset(tcfg, sz, n, tcfg->buf_off[j]);
				INFO("Buf %d Node %d offset %p\n", j, n, tcpu->b[j]);
			}
		}
	}
}


static int
alloc_mmio_mem(struct tcfg *tcfg)
{
	int fd;
	int i;

	for (i = 0; i < NUM_ADDR_MAX; i++) {
		void *addr;
		char *fname;

		if (tcfg->mmio_mem[i].sz == 0)
			continue;

		fname = tcfg->mmio_mem[i].bfile;
		fd = open(fname, O_RDWR);
		if (fd < 0) {
			ERR("Error opening file : %s : %s\n", strerror(errno), fname);
			return -errno;
		}

		addr = mmap(NULL, tcfg->mmio_mem[i].sz, PROT_READ | PROT_WRITE,
			MAP_POPULATE | MAP_SHARED, fd, tcfg->mmio_mem[i].mmio_offset);
		if (addr == MAP_FAILED) {
			ERR("Error mapping mmio: %s : %s\n", strerror(errno), fname);
			close(fd);
			return -errno;
		}

		close(fd);
		tcfg->mmio_mem[i].base_addr = addr;
	}

	return 0;
}

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

		if (nm->sz == 0)
			continue;

		addr = NULL;
		rc = alloc_node_mem(tcfg, nm->sz, i, &addr);
		if (rc)
			return rc;
		INFO("Node %d: %p size 0x%016lx\n", i, addr, nm->sz);
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

			if (tcfg->mmio_mem[j].bfile) {
				int idx = tcfg->mmio_fd_idx[j];
				ba = (uint64_t)tcfg->mmio_mem[idx].base_addr;
			} else
				ba = numa_base_addr(tcfg, buffer_id_to_node(tcpu, j));

			PTR_ADD(tcpu->b[j], ba);
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
	rc = alloc_mmio_mem(tcfg);
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
	tcpu->qd = tcfg->qd == 0 ? tcpu->wq_info->size : tcfg->qd;
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
		tcpu->err = dmap(fd, tcpu->bcomp,
				ALIGN(tcfg->nb_desc * comp_rec_cache_aligned_size(tcpu)));
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
		dmap(fd, tcpu->bcomp, ALIGN(tcfg->nb_desc * comp_rec_cache_aligned_size(tcpu)));

 unmap_comp:
	dunmap(fd, tcpu->comp, ALIGN(tcfg->nb_bufs * sizeof(tcpu->comp[0]) * 2));

 unmap_bdesc:
	if (tcfg->batch_sz > 1)
		dunmap(fd, tcpu->bdesc, ALIGN(tcfg->nb_desc * sizeof(tcpu->bdesc[0])));
 unmap_desc:
	dunmap(fd, tcpu->desc, ALIGN(tcfg->nb_bufs * sizeof(tcpu->desc[0])));

	return err;
}

static size_t
op_priv_size(struct tcfg *tcfg)
{
	struct tcfg_cpu tcpu;
	uint32_t nb_blocks;

	switch (tcfg->op) {

	case DSA_OPCODE_CRCGEN:
	case DSA_OPCODE_COPY_CRC:
		return tcfg->nb_bufs * sizeof(tcpu.crc[0]);

	case DSA_OPCODE_DIF_INS:
	case DSA_OPCODE_DIF_UPDT:
		nb_blocks = tcfg->blen/tcfg->bl_len;
		return nb_blocks * sizeof(tcpu.dif_tag[0]);

	default:
		return 0;
	}
}

static int
test_init_op_priv(struct tcfg_cpu *tcpu)
{
	size_t sz = op_priv_size(tcpu->tcfg);

	if (!sz)
		return 0;

	return (tcpu->op_priv = calloc(1, sz)) != NULL ? 0 : -ENOMEM;
}

static void
test_free_op_priv(struct tcfg_cpu *tcpu)
{
	free(tcpu->op_priv);
	tcpu->op_priv = NULL;
}

void
test_init_percpu(struct tcfg_cpu *tcpu)
{
	tcpu->err = test_init_op_priv(tcpu);
	if (tcpu->err)
		return;

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
	dunmap(fd, tcpu->bcomp, ALIGN(tcfg->nb_desc * comp_rec_cache_aligned_size(tcpu)));

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

	for (i = 0; tcfg->op_info && i < tcfg->op_info->nb_buf; i++) {
		munmap(tcfg->mmio_mem[i].base_addr, align(tcfg->mmio_mem[i].sz, 4096));
		free(tcfg->mmio_mem[i].bfile);
	}

	if (tcfg->tcpu) {
		for (i = 0; i < tcfg->nb_cpus; i++) {
			free(tcfg->tcpu[i].dname);
			test_free_op_priv(&tcfg->tcpu[i]);
		}
		munmap(tcfg->tcpu, align(tcfg->nb_cpus * sizeof(*tcfg->tcpu), 4096));
	}

	test_barrier_free(tcfg);
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

	poll_comp_common(&comp, &poll_cnt, flags, ~0UL);
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

static
int init_numa_node(struct tcfg *tcfg, int nb_numa_node)
{
	int nb_cpu_node = 0;	/* cpu node count */
	int (*numa_node)[NUM_ADDR_MAX] = NULL;
	int *numa_nb_cpu = NULL;
	struct numa_mem *nm = NULL;
	int i, j;
	int rc;

	numa_node = calloc(nb_numa_node, sizeof(numa_node[0]));
	if (!numa_node)
		return -ENOMEM;

	numa_nb_cpu = calloc(nb_numa_node, sizeof(numa_nb_cpu[0]));
	if (!numa_nb_cpu) {
		rc = -ENOMEM;
		goto err_ret;
	}

	nm = calloc(nb_numa_node, sizeof(nm[0]));
	if (!nm) {
		rc = -ENOMEM;
		goto err_ret;
	}

	tcfg->numa_mem = nm;
	tcfg->numa_nb_cpu = numa_nb_cpu;

	for (i = 0; i < tcfg->nb_cpus; i++) {
		int n;

		cpu_pin(tcfg->tcpu[i].cpu_num);
		n = node_id();
		tcfg->tcpu[i].numa_node = n;
		if (numa_nb_cpu[n] == 0)
			nb_cpu_node++;
		numa_nb_cpu[n]++;
	}

	if (tcfg->nb_numa_node == 0) {
		for (i = 0; i < nb_numa_node; i++)
			memmove(&numa_node[i], &tcfg->numa_node_default[i],
				sizeof(tcfg->numa_node[0]));
		tcfg->nb_numa_node = nb_numa_node;
		tcfg->numa_node = numa_node;
		return 0;
	}

	if (tcfg->nb_numa_node && tcfg->nb_numa_node != nb_cpu_node) {
		ERR("Numa specifiers (%d) does not match numa node count (%d)\n",
			tcfg->nb_numa_node, nb_cpu_node);
		rc = -EINVAL;
		goto err_ret;
	}

	j = 0;
	for (i = 0; i < nb_numa_node; i++) {

		if (numa_nb_cpu[i] == 0)
			continue;

		memmove(&numa_node[i], &tcfg->numa_node[j], sizeof(numa_node[0]));
		j++;
	}

	free(tcfg->numa_node);

	tcfg->nb_numa_node = nb_numa_node;
	tcfg->numa_node = numa_node;

	return 0;

err_ret:
	free(numa_node);
	free(numa_nb_cpu);
	free(nm);

	return rc;
}

int
test_init_global(struct tcfg *tcfg)
{
	int err;

	err = system_init();
	if (err)
		return err;

	err = init_numa_node(tcfg, numa_max_node() + 1);
	if (err)
		return err;

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
