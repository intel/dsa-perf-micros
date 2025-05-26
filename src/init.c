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
#include <sys/ioctl.h>
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
#include <numa.h>

#include "common.h"
#include "dsa.h"
#include "device.h"
#include "util.h"
#include "init.h"

#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#endif
#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)
#endif

#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
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

	cs = align_hv(cs, CACHE_LINE_SIZE);

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
				tcpu->b[j][0] = alloc_mmio_offset(tcfg, sz, j, tcfg->buf_off[j]);
			else {
				int n = buffer_id_to_node(tcpu, j);
				tcpu->b[j][0] = alloc_numa_offset(tcfg, sz, n, tcfg->buf_off[j]);
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
init_nm(struct tcfg *tcfg, int n)
{
	struct numa_mem *nm = &tcfg->numa_mem[n];
	uint32_t huge_flags[] = {0, MFD_HUGETLB | MFD_HUGE_2MB, MFD_HUGETLB | MFD_HUGE_1GB};
	int fd;

	fd = memfd_create("temp", huge_flags[tcfg->pg_size]);
	if (fd < 0) {
		ERR("Error creating memfd failed: %s\n", strerror(errno));
		return -errno;
	}

	nm->fd = fd;
	nm->offset = 0;
	nm->sz = 0;

	return 0;
}

static int
alloc_node_mem(struct tcfg *tcfg, uint64_t sz, int n, void **paddr)
{
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


	fd = tcfg->numa_mem[n].fd;

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
alloc_numa_mem_contig(struct tcfg *tcfg)
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
			char ***pb = (char ***)((char *)tcpu + off);
			int k;

			if (tcfg->mmio_mem[j].bfile) {
				int idx = tcfg->mmio_fd_idx[j];
				ba = (uint64_t)tcfg->mmio_mem[idx].base_addr;
			} else
				ba = numa_base_addr(tcfg, buffer_id_to_node(tcpu, j));

			PTR_ADD(tcpu->b[j][0], ba);
			for (k = 0; k < tcfg->nb_bufs; k++)
				tcpu->b[j][k] = tcpu->b[j][0] +  k * tcfg->bstride_arr[j];

			*pb = tcpu->b[j];
		}

	}

	if (tcfg->pg_size != 0)
		return;
}

static int
alloc_buf_addr_array(struct tcfg *tcfg)
{
	int i, j;

	for (i = 0; i < tcfg->nb_cpus; i++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

		for (j = 0; j < tcfg->op_info->nb_buf; j++) {
			tcpu->b[j] = calloc(1, tcfg->nb_bufs * sizeof(tcpu->b[j][0]));
			if (!tcpu->b[j])
				return -ENOMEM;
		}
	}

	return 0;
}

static void
free_buf_addr_array(struct tcfg *tcfg)
{
	int i, j;

	for (i = 0; i < tcfg->nb_cpus; i++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

		for (j = 0; j < tcfg->op_info->nb_buf; j++)
			free(tcpu->b[j]);
	}
}

static int
test_do_contig_mmap(struct tcfg *tcfg)
{
	int rc;

	alloc_buf_offsets(tcfg);

	rc = alloc_numa_mem_contig(tcfg);
	if (rc)
		return rc;

	rc = alloc_mmio_mem(tcfg);
	if (rc)
		return rc;
	add_base_addr(tcfg);

	return 0;
}

static int
bind_alloc(int n)
{
	uint64_t nodemask = 1ULL << n;
	int rc;

	if (n == -1)
		return set_mempolicy(MPOL_DEFAULT, NULL, 64);

	rc = set_mempolicy(MPOL_BIND, &nodemask, 64);
	if (rc) {
		ERR("failed to bind memory range %s\n", strerror(errno));
		return -errno;
	}

	return 0;
}

/* 64T Mapping works */
#define EMPTY_MAP (80 * 1024UL * 1024UL * 1024UL * 1024UL)

static char *
get_avail_va(void)
{
	char *p;

	p = mmap(NULL,
		EMPTY_MAP,
		PROT_NONE,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1,
		0);

	munmap(p, EMPTY_MAP);

	if (p == MAP_FAILED) {
		ERR("mmap failed\n");
		return MAP_FAILED;
	}

	return align_lp(p, 1024 * 1024 * 1024);
}

static char *free_p;

static int
numa_node_desc_comp_size(struct tcfg *tcfg, int n)
{
	struct tcfg_cpu *tcpu = &tcfg->tcpu[0];
	int sz = tcfg->numa_nb_cpu[n] * tcfg->nb_bufs * (sizeof(tcpu->desc[0]));

	sz += tcfg->numa_nb_cpu[n] * tcfg->nb_bufs * (sizeof(tcpu->comp[0])) *  2;

	if (tcfg->batch_sz == 1)
		return sz;

	sz += tcfg->numa_nb_cpu[n] * tcfg->nb_desc * (sizeof(tcpu->desc[0]));
	sz += tcfg->numa_nb_cpu[n] * tcfg->nb_desc * (sizeof(tcpu->comp[0])) *2;

	return sz;
}

static int
resize_nm(struct tcfg *tcfg, int n, uint64_t sz)
{
	struct numa_mem *nm = &tcfg->numa_mem[n];
	uint64_t new_sz;
	int rc;

	new_sz = nm->offset + sz;
	if (new_sz <= nm->sz)
		return 0;

	new_sz = page_align_sz(tcfg, new_sz);

	rc = ftruncate(nm->fd, new_sz);
	if (!rc)
		nm->sz = new_sz;
	else {
		ERR("ftruncate failed %s\n", strerror(errno));
		return -errno;
	}

	return 0;
}

static void
init_desc_comp_ptr(struct tcfg *tcfg, int n, void *p)
{
	struct tcfg_cpu *tcpu = &tcfg->tcpu[0];
	int desc_sz = tcfg->nb_bufs * (sizeof(tcpu->desc[0]));
	int comp_sz = tcfg->nb_bufs * (sizeof(tcpu->comp[0])) *  2;
	int bdesc_sz = tcfg->nb_desc * (sizeof(tcpu->desc[0]));
	int bcomp_sz = tcfg->nb_desc * (sizeof(tcpu->comp[0]));
	void *t = p;
	int j;

	for (j = 0; j < tcfg->nb_cpus && tcfg->dma; j++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[j];

		if (tcpu->numa_node != n)
		       continue;

		tcpu->desc = t;
		PTR_ADD(t, desc_sz);
		tcpu->comp = t;
		PTR_ADD(t, comp_sz);

		if (tcfg->batch_sz > 1) {
			tcpu->bdesc = t;
			PTR_ADD(t, bdesc_sz);
			tcpu->bcomp = t;
			PTR_ADD(t, bcomp_sz);
		}
	}
}

static int
alloc_numa_node_desc_comp(struct tcfg *tcfg, char *start, int n)
{
	struct numa_mem *nm = &tcfg->numa_mem[n];
	uint64_t desc_comp_sz = numa_node_desc_comp_size(tcfg, n);
	uint64_t pg_sz = page_sz(tcfg);
	char *p;

	p = mmap(align_lp(start, pg_sz),
		page_align_sz(tcfg, desc_comp_sz),
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_POPULATE | MAP_FIXED,
		nm->fd,
		align_lv(nm->offset, pg_sz));

	if (p == MAP_FAILED) {
		ERR("mmap failed: %s\n", strerror(errno));
		return -errno;
	}

	nm->desc_comp = p;
	nm->desc_comp_sz = desc_comp_sz;

	init_desc_comp_ptr(tcfg, n, nm->desc_comp + nm->offset % pg_sz);

	return 0;
}

static int
alloc_bufs(struct tcfg *tcfg, int cpu, int b, int n)
{
	struct tcfg_cpu *tcpu = &tcfg->tcpu[cpu];
	struct numa_mem *nm = &tcfg->numa_mem[n];
	uint64_t pg_sz = page_sz(tcfg);
	int k;

	free_p = align_hp(free_p, pg_sz);

	for (k = 0; k < tcfg->nb_bufs; k++) {

		free_p = mmap(align_lp(free_p, pg_sz),
			page_align_sz(tcfg, tcfg->blen),
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE | MAP_FIXED,
			nm->fd,
			align_lv(nm->offset, pg_sz));
		if (free_p == MAP_FAILED) {
			ERR("mmap 1 failed %s, buffer [%d]\n",
					strerror(errno), k);
			return -errno;
		}

		tcpu->b[b][k] = free_p + nm->offset % pg_sz;
		free_p += tcfg->bstride;
		nm->offset += tcfg->blen;
	}

	return 0;
}

static int
alloc_numa_node_sparse(struct tcfg *tcfg, int n)
{
	struct numa_mem *nm = &tcfg->numa_mem[n];
	int i, j;
	int desc_comp_len;
	int rc;

	rc = 0;
	bind_alloc(n);

	for (i = 0; i < tcfg->nb_cpus; i++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

		for (j = 0; j < tcfg->op_info->nb_buf; j++) {
			uint32_t offb = tcfg->op_info->b_off[j];
			char ***pb = (char ***)((char *)tcpu + offb);
			int rc;

			if (n != buffer_id_to_node(tcpu, j))
				continue;

			rc = resize_nm(tcfg, n, tcfg->nb_bufs * tcfg->blen);
			if (rc)
				return rc;

			rc = alloc_bufs(tcfg, i, j, n);
			if (rc)
				return rc;
			*pb = tcpu->b[j];
		}
	}

	desc_comp_len = numa_node_desc_comp_size(tcfg, n);
	if (desc_comp_len == 0)
		goto done;

	/*
	 * 4K page sizes are most common, start descriptor memory on a separate
	 * 4K page (true of most applications)
	 */
	nm->offset = align_hv(nm->offset, 4096);

	rc = resize_nm(tcfg, n, desc_comp_len);
	if (rc)
		return rc;

	rc = alloc_numa_node_desc_comp(tcfg, free_p, n);
	if (!rc) {
		free_p += page_align_sz(tcfg, desc_comp_len);
		nm->offset += desc_comp_len;
	}

 done:
	bind_alloc(-1);

	return rc;
}

static int
test_do_large_stride(struct tcfg *tcfg)
{
	int i;
	int rc;

	free_p = get_avail_va();
	if (free_p == MAP_FAILED) {
		ERR("Failed to mmap region of size 0x%lx\n", EMPTY_MAP);
		return -ENOMEM;
	}

	for (i = 0; i < tcfg->nb_numa_node; i++) {
		rc = alloc_numa_node_sparse(tcfg, i);
		if (rc)
			break;
	}

	return rc;
}

static int
test_init_mem(struct tcfg *tcfg)
{
	int rc;
	int i;

	rc = alloc_buf_addr_array(tcfg);
	if (rc)
		return rc;

	for (i = 0; !rc && i < tcfg->nb_numa_node; i++) {
		rc = init_nm(tcfg, i);
		if (rc)
			return rc;
	}

	return tcfg->large_stride ?
				test_do_large_stride(tcfg) :
				test_do_contig_mmap(tcfg);

}

static int
test_init_wq(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	int rc = 0;

	if (!tcfg->dma)
		goto func_exit;

	tcpu->wq_info = malloc(sizeof(*tcpu->wq_info));
	if (!tcpu->wq_info) {
		ERR("Failed to allocate memory for wq info\n");
		rc = -ENOMEM;
		goto func_exit;
	}

	tcpu->wq = wq_map(tcpu->dname, tcpu->wq_id, tcfg->wq_type == 1,
			node_id(), &tcpu->wq_fd);
	if (tcpu->wq == NULL) {
		ERR("Failed to map WQ\n");
		free(tcpu->wq_info);
		tcpu->wq_info = NULL;
		rc = -ENOMEM;
		goto func_exit;
	}

	wq_info_get(tcpu->wq, tcpu->wq_info);

	tcpu->dwq = tcpu->wq_info->dwq;
	tcpu->qd = tcfg->qd == 0 ? tcpu->wq_info->size : tcfg->qd;
	tcpu->qd = min(tcpu->qd, tcfg->nb_desc);

	INFO("CPU %d dname %s wq size %d shared %d qd %d\n", tcpu->cpu_num,
		tcpu->wq_info->dname, tcpu->wq_info->size, !tcpu->wq_info->dwq,
		tcpu->qd);

func_exit:
	tcpu->wq_init_done = true;
	return rc;
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

		tcpu->err = dmap(fd, tcpu->b[i][0], ALIGN(sz));
		if (tcpu->err) {
			err = tcpu->err;
			goto unmap_buf;
		}
	}

	return 0;

 unmap_buf:
	for (i = i - 1; i >= 0; i--) {
		uint64_t sz = tcfg->bstride_arr[i] * tcfg->nb_bufs;

		dunmap(fd, tcpu->b[i][0], ALIGN(sz));
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
	case DSA_OPCODE_DIX_GEN:
		nb_blocks = tcfg->blen/tcfg->bl_len;
		return nb_blocks * sizeof(tcpu.dif_tag[0]);

	default:
		return 0;
	}
}

static int
find_next_bit(struct bitmask *mask, int n, int *p)
{
	int i;

	for (i = n; i < numa_bitmask_nbytes(mask) * 8; i++) {
		if (numa_bitmask_isbitset(mask, i)) {
			*p = i;
			return 0;
		}
	}

	for (i = 0; i < n && i < numa_bitmask_nbytes(mask) * 8; i++) {
		if (numa_bitmask_isbitset(mask, i)) {
			*p = i;
			return 0;
		}
	}

	return -ESRCH;
}

static int
set_owner_cpus(struct tcfg *tcfg)
{
	struct bitmask **cpu_mask = NULL;
	int *next_cpu = NULL;
	int rc = 0;
	int nb_numa_nodes, owners_per_submitter;
	int i, j, n, owner_index;
	struct tcfg_cpu *tcpu;

	nb_numa_nodes = numa_max_node() + 1;
	cpu_mask = calloc(nb_numa_nodes, sizeof(*cpu_mask));
	if (!cpu_mask)
		goto err_ret;

	next_cpu = calloc(nb_numa_nodes, sizeof(*next_cpu));
	if (!next_cpu)
		goto err_ret;

	for (i = 0; i < nb_numa_nodes; i++) {
		next_cpu[i] = -1;
		cpu_mask[i] = numa_allocate_cpumask();
		if (!cpu_mask[i])
			goto err_ret;
		numa_node_to_cpus(i, cpu_mask[i]);
	}

	numa_bitmask_clearbit(cpu_mask[0], 0);

	for (i = 0; i < tcfg->nb_cpus; i++) {
		tcpu = &tcfg->tcpu[i];
		numa_bitmask_clearbit(cpu_mask[tcpu->numa_node], tcpu->cpu_num);
	}

	owners_per_submitter = 1 + (tcfg->id_oper == 3);
	for (i = 0; i < tcfg->nb_cpus; i++) {
		tcpu = &tcfg->tcpu[i];
		for (j = 0; j < owners_per_submitter; j++) {
			n = tcpu->numa_node;
			rc = find_next_bit(cpu_mask[n], next_cpu[n] + 1, &next_cpu[n]);
			if (rc) {
				/* If any issue in finding CPU, assign CPU 0 */
				next_cpu[n] = 0;
			}

			owner_index = (owners_per_submitter == 1)
						? (tcfg->id_oper == 0x1) ? 0 : 1
						: j;
			tcfg->id_owners[tcpu->id_owner_idx[owner_index]].c = next_cpu[n];
		}
	}

err_ret:
	for (i = 0; i < nb_numa_nodes; i++)
		numa_free_cpumask(cpu_mask[i]);
	free(cpu_mask);
	free(next_cpu);

	return rc;
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

static int
get_owner_wq(struct tcfg *tcfg, int owner_idx, int *wq_fd, void **wq, bool *dedicated)
{
	struct wq_info wq_info;

	*wq = wq_map(tcfg->id_owners[owner_idx].d,
			tcfg->id_owners[owner_idx].q,
			1,
			node_id(),
			wq_fd);
	if (*wq == NULL) {
		if (tcfg->id_owners[owner_idx].q == -1) {
			/* If shared WQ is not found, then try to get a free DWQ */
			*wq = wq_map(tcfg->id_owners[owner_idx].d,
					tcfg->id_owners[owner_idx].q,
					0,
					node_id(),
					wq_fd);
			if (*wq == NULL)
				return -ENOMEM;
		} else
			return -ENOMEM;
	}

	wq_info_get(*wq, &wq_info);
	*dedicated = wq_info.dwq;

	return 0;
}

static void
get_owner_window_size_base(struct tcfg *tcfg, uint64_t *win_base, uint64_t *sz)
{
	int i, j, k;

	/* Creating the window as entire address range to simplify */
	/* For window disable, we need to set size = 0 */
	*win_base = 0;
	*sz = tcfg->id_window_enable ? ~0L : 0;

	/* mmap(MAP_POPULATE) but generates a fault on write after fork */
	for (k = 0; k < tcfg->nb_cpus; k++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[k];
		for (i = 0; i < tcfg->op_info->nb_buf; i++)
			for (j = 0; j < tcfg->nb_bufs; j++)
				faultin_range(tcpu->b[i][j], tcfg->blen_arr[i]);
	}
}

static int
init_id_owners(struct tcfg *tc)
{
	int owners_per_submitter = 1 + (tc->id_oper == 3);
	int owner_idx, sub_idx, i;
	struct cpu_wq_info *owner;
	struct id_owner_info *id_owner_info;
	struct tcfg_cpu *tcpu;

	tc->id_owner_info = mmap(NULL, tc->id_nb_owners * sizeof(struct id_owner_info),
					PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (tc->id_owner_info == MAP_FAILED) {
		ERR("Failed to allocate inter domain owner info array\n");
		return -ENOMEM;
	}

	for (sub_idx = 0; sub_idx < tc->nb_cpus; sub_idx++) {
		tcpu = &tc->tcpu[sub_idx];
		owner_idx = tc->id_idpte_type == IDXD_WIN_TYPE_SA_MS
				? owner_seq_no(tc, tcpu->dname, sub_idx + 1)
					* owners_per_submitter
				: sub_idx * owners_per_submitter;

		for (i = 0; i < owners_per_submitter; i++) {
			owner = &tc->id_owners[owner_idx + i];
			id_owner_info = &tc->id_owner_info[owner_idx + i];

			id_owner_info->idpte_fd = mmap(NULL, tc->id_window_cnt * sizeof(int),
								PROT_READ | PROT_WRITE,
								MAP_SHARED | MAP_ANONYMOUS, -1, 0);

			if (!id_owner_info->sub_idx) {
				id_owner_info->sub_idx = mmap(NULL, tc->nb_cpus * sizeof(int),
								PROT_READ | PROT_WRITE,
								MAP_SHARED | MAP_ANONYMOUS, -1, 0);
				if (id_owner_info->sub_idx == MAP_FAILED) {
					ERR("Failed to allocate sub_idx array\n");
					return -ENOMEM;
				}
				id_owner_info->nb_sub = 0;
			}

			if (owners_per_submitter == 1) {
				if (tc->id_oper == 0x1) {
					tcpu->id_owner_idx[0] = owner_idx + i;
					tcpu->id_owner_idx[1] = -1;
				}
				if (tc->id_oper == 0x2) {
					tcpu->id_owner_idx[0] = -1;
					tcpu->id_owner_idx[1] = owner_idx + i;
				}
			} else
				tcpu->id_owner_idx[i] = owner_idx + i;

			id_owner_info->sub_idx[id_owner_info->nb_sub++] = sub_idx;

			if (tcpu->tcfg->id_owners_given) {
				if (strcmp(tcpu->dname, owner->d) != 0) {
					ERR("DSA device mismatch for submitter and owner\n");
					return -EINVAL;
				}
			} else {
				owner->d = tcpu->dname;
				owner->q = -1;
			}
		}
	}
	return 0;
}

static int
create_idpt_window(struct tcfg *tcfg, int owner_idx,
			struct idxd_win_param *win_param_arr,
			int id_window_cnt)
{
	uint64_t win_base, sz = 0;
	struct id_owner_info *id_owner_info = &tcfg->id_owner_info[owner_idx];
	int i;

	get_owner_window_size_base(tcfg, &win_base, &sz);
	struct idxd_win_param win_param = {.size = sz, .base = win_base,
			.flags = IDXD_WIN_FLAGS_PROT_READ | IDXD_WIN_FLAGS_PROT_WRITE,
			.type = tcfg->id_idpte_type};

	if (tcfg->id_window_enable)
		win_param.flags |= IDXD_WIN_FLAGS_WIN_CHECK;
	if (tcfg->id_window_mode == IDPTE_OFFSET_MODE)
		win_param.flags |= IDXD_WIN_FLAGS_OFFSET_MODE;

	for (i = 0; i < id_window_cnt; i++) {
		win_param_arr[i] = win_param;

		/* Window creation */
		id_owner_info->idpte_fd[i] = ioctl(id_owner_info->wq_fd,
							IDXD_WIN_CREATE, &win_param_arr[i]);
		id_owner_info->wnd_status = (id_owner_info->idpte_fd[i] >= 0);
		if (id_owner_info->idpte_fd[i] < 0) {
			ERR("Failed to create idpt window for owner = %d, window# %d\n",
				owner_idx, i);
			return -errno;
		}
		INFO("Inter domain window created with base = 0x%lx | size = 0x%lx | "
			"flags = 0x%x | type = 0x%x"
			" -- handle = 0x%x\n", win_param.base, win_param.size, win_param.flags,
			win_param.type, win_param.handle);
	}
	return 0;
}

static int
update_idpt_window(struct id_owner_info *id_owner_info,
			struct idxd_win_param *win_param_arr,
			int id_window_cnt)
{
	struct dsa_completion_record comp __attribute__ ((aligned(32))) = {0};
	struct dsa_hw_desc updt_desc = {.completion_addr = (uint64_t)&comp,
					.flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR,
					.opcode = DSA_OPCODE_UPDATE_WIN};
	struct idxd_win_param *win_param;
	int i;

	for (i = 0; i < id_window_cnt; i++) {
		win_param = &win_param_arr[i];
		updt_desc.win_base_addr = win_param->base;
		updt_desc.win_size = win_param->size;
		updt_desc.idpt_win_handle = win_param->handle;
		updt_desc.idpt_win_flags = win_param->flags;

		dsa_desc_submit(id_owner_info->wq, id_owner_info->is_dwq, &updt_desc);

		if (poll_comp_common(&comp, NULL, 0, MAX_COMP_RETRY)) {
			ERR("Window update didn't complete\n");
			return -errno;
		}

		INFO("Update Window Successful.\n");
	}
	return 0;
}

static int
update_window_loop(struct tcfg *tcfg, struct id_owner_info *id_owner_info,
			struct idxd_win_param *win_param)
{
	int i, j, rc, completed, curr_owner_idx;
	struct id_owner_info *curr_id_owner_info;
	struct tcfg_cpu *tcpu;

	while(1) {
		/**
		 * Loop thru all the submitters for the owner until test is complete or
		 * errored out.
		 */
		completed = 0;
		for (i = 0; i < id_owner_info->nb_sub; i++) {
			tcpu = &tcfg->tcpu[id_owner_info->sub_idx[i]];
			if (tcpu->err) {
				INFO("Test error received for cpu %d\n", i);
				return 1;
			}
			if (tcpu->test_completed) {
				INFO("Test completion received for cpu %d\n", i);
				completed++;
				if (completed == id_owner_info->nb_sub)
					return 0;
			}
			for (j = 0; j < NUM_ID_ADDRS; j++) {
				curr_owner_idx = tcpu->id_owner_idx[j];
				if (curr_owner_idx == -1)
					continue;
				curr_id_owner_info = &tcfg->id_owner_info[curr_owner_idx];
				if (curr_id_owner_info != id_owner_info)
					continue;

				if (tcpu->updt_wnd_cnt[j].prod > tcpu->updt_wnd_cnt[j].cons)
				{
					rc = update_idpt_window(id_owner_info, win_param,
								tcfg->id_window_cnt);
					if (rc) {
						ERR("Update Window failed for cpu %d\n", i);
						return rc;
					}
					++tcpu->updt_wnd_cnt[j].cons;
				}
			}
		}
	}
	return 0;
}

static int
init_interdomain_owner(struct tcfg* tcfg, struct id_owner_info* id_owner_info, int owner_idx)
{
	int i, rc = 0;
	struct idxd_win_param *win_param_arr;
	/**
	* Wait for all submitters to init their respective wqs so that an
	* owner doesn't pick up a wq which is used by a submitter unless SWQ
	*/
	for (i = 0; i < tcfg->nb_cpus; i++) {
		while (!tcfg->tcpu[i].wq_init_done)
			sleep(1);
	}

	cpu_pin(tcfg->id_owners[owner_idx].c);

	rc = get_owner_wq(tcfg, owner_idx, &id_owner_info->wq_fd,
		&id_owner_info->wq, &id_owner_info->is_dwq);
	if (rc) {
		ERR("Failed to map WQ\n");
		id_owner_info->wnd_status = -1;
		return rc;
	}

	win_param_arr = calloc(tcfg->id_window_cnt, sizeof(struct idxd_win_param));
	if (!win_param_arr) {
		ERR("Could not allocate win_param_arr\n");
		return EXIT_FAILURE;
	}
	rc = create_idpt_window(tcfg, owner_idx, win_param_arr, tcfg->id_window_cnt);
	if (rc) {
		id_owner_info->wnd_status = -1;
		free(win_param_arr);
		return EXIT_FAILURE;
	}

	rc = update_window_loop(tcfg, id_owner_info, win_param_arr);

	free(win_param_arr);
	for (i = 0; i < tcfg->id_window_cnt; i++)
		close(id_owner_info->idpte_fd[i]);

	return EXIT_SUCCESS;
}

static void *
init_interdomain_owner_fn(void *arg)
{
	struct id_owner_info *id_owner_info = arg;
	int rc;

	rc = init_interdomain_owner(
		id_owner_info->tcfg, id_owner_info, id_owner_info->owner_idx);

	if (id_owner_info->tcfg->proc)
		exit(rc);
	else
		pthread_exit(NULL);
}

static int
test_init_inter_domain_global(struct tcfg *tcfg)
{
	int j, pid, rc = 0, err;
	struct id_owner_info *id_owner_info;

	if (!IS_INTER_DOMAIN_OP(tcfg->op))
		return 0;

	rc = init_id_owners(tcfg);
	if (rc)
		return rc;

	if (!tcfg->id_owners_given) {
		rc = set_owner_cpus(tcfg);
		if (rc)
			return rc;
	}

	for (j = 0; j < tcfg->id_nb_owners; j++) {
		id_owner_info = &tcfg->id_owner_info[j];
		id_owner_info->owner_idx = j;
		id_owner_info->tcfg = tcfg;
		if (tcfg->proc) {
			pid = fork();
			if (pid == -1) {
				ERR("Failed to create owner process - error no - %s\n", strerror(errno));
				return -errno;
			}
			if (pid == 0) {
				init_interdomain_owner_fn((void*)(id_owner_info));
			} else {
				id_owner_info->pid = pid;
			}
		} else {
			err = pthread_create(&id_owner_info->tid, NULL, init_interdomain_owner_fn,
				(void*)(id_owner_info));
			if(err)
				ERR("Thread creation failed");
			id_owner_info->pid = getpid();
		}
	}
	return 0;
}

static int
inter_domain_window_attach(struct tcfg_cpu *tcpu, struct id_owner_info *owner, int addr_idx)
{
	int rc, j, opid_fd = 0;
	struct idxd_win_attach win_attach = {0};

	if (tcpu->tcfg->proc) {
		opid_fd = syscall(SYS_pidfd_open, owner->pid, 0);
		if (opid_fd == -1) {
			ERR("Error in pidfd_open for owner pid = %d : %s\n",
				owner->pid, strerror(errno));
			return -errno;
		}
	}

	tcpu->id_handle[addr_idx] = calloc(tcpu->tcfg->id_window_cnt, sizeof(uint16_t));
	if (!tcpu->id_handle[addr_idx]) {
		ERR("Failed to allocate for Interdomain handle\n");
		close(opid_fd);
		return -ENOMEM;
	}

	for (j = 0; j < tcpu->tcfg->id_window_cnt; j++) {
		if (tcpu->tcfg->proc) {
			tcpu->idpte_fd[j] = syscall(__NR_pidfd_getfd,
							opid_fd, owner->idpte_fd[j], 0);
			if (tcpu->idpte_fd[j] == -1) {
				ERR("Error in pidfd_getfd for owner pid = %d, ioctl fd = %d: %s\n",
					owner->pid, owner->idpte_fd[j], strerror(errno));
				close(opid_fd);
				return -errno;
			}
		}
		else {
			tcpu->idpte_fd[j] = owner->idpte_fd[j];
		}

		win_attach.fd = tcpu->idpte_fd[j];
		rc = ioctl(tcpu->wq_fd, IDXD_WIN_ATTACH, &win_attach);

		if (rc < 0) {
			ERR("Window attach failed for owner %d, submiiter %d: %s\n",
				tcpu->id_owner_idx[addr_idx], *owner->sub_idx, strerror(errno));
			if (tcpu->tcfg->proc)
				close(opid_fd);
			return -errno;
		}
		tcpu->id_handle[addr_idx][j] = win_attach.handle;
	}
	if (tcpu->tcfg->proc)
		close(opid_fd);

	return 0;
}

static int
test_init_inter_domain_per_cpu(struct tcfg_cpu *tcpu)
{
	int rc = 0, i;
	struct id_owner_info *owner;

	if (!IS_INTER_DOMAIN_OP(tcpu->tcfg->op))
		return 0;

	tcpu->idpte_fd = calloc(tcpu->tcfg->id_window_cnt, sizeof(int));
	if (!tcpu->idpte_fd) {
		ERR("Failed to allocate for Interdomain fd\n");
		return -ENOMEM;
	}

	for (i = 0; i < NUM_ID_ADDRS; i++) {
		if ((tcpu->tcfg->id_oper & (1U << i)) == 0)
			continue;

		owner = &tcpu->tcfg->id_owner_info[tcpu->id_owner_idx[i]];
		INFO("Waiting for ID window to be created...\n");
		while (!owner->wnd_status)
			sleep(1);
		INFO("Submitter : Owner ID window created.\n");
		/* If any error while creating the IDPTE window, then return error */
		if (owner->wnd_status == -1) {
			ERR("Owner %d window creation seems to have failed. Aborting...\n",
				tcpu->id_owner_idx[i]);
			return -1;
		}

		rc = inter_domain_window_attach(tcpu, owner, i);
	}
	return rc;
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

	tcpu->err = test_init_inter_domain_per_cpu(tcpu);
	if (tcpu->err)
		return;

	tcpu->err = test_init_dmap(tcpu);
}

void
dunmap_per_cpu(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	int fd, i, j;

	if (!tcfg->dma || !tcpu->wq_info)
		return;

	tcpu->test_completed = true; /* Used to notify inter-domain owner */

	fd = tcpu->wq_info->dmap_fd;

	dunmap(fd, tcpu->desc, ALIGN(tcfg->nb_bufs * sizeof(tcpu->desc[0])));

	if (tcfg->batch_sz > 1)
		dunmap(fd, tcpu->bdesc, ALIGN(tcfg->nb_desc * sizeof(tcpu->bdesc[0])));

	dunmap(fd, tcpu->comp, ALIGN(tcfg->nb_bufs * sizeof(tcpu->comp[0]) * 2));
	dunmap(fd, tcpu->bcomp, ALIGN(tcfg->nb_desc * comp_rec_cache_aligned_size(tcpu)));

	for (i = 0; i < tcfg->op_info->nb_buf; i++) {
		uint64_t sz = tcfg->bstride_arr[i] * tcfg->nb_bufs;

		dunmap(fd, tcpu->b[i][0], ALIGN(sz));
	}

	if (IS_INTER_DOMAIN_OP(tcfg->op)) {
		for (j = 0; j < tcfg->id_window_cnt; j++)
			close(tcpu->idpte_fd[j]);
		free(tcpu->idpte_fd);
		for (j = 0; j < NUM_ID_ADDRS; j++)
			free(tcpu->id_handle[j]);
	}
}

static void
test_do_sparse_munmap(struct tcfg *tcfg)
{
	unsigned int i, j, k;
	int rc;

	for (i = 0; i < tcfg->nb_cpus; i++) {
		struct tcfg_cpu *tcpu = &tcfg->tcpu[i];

		for (j = 0; j < tcfg->op_info->nb_buf; j++) {
			for (k = 0; k < tcfg->nb_bufs; k++) {
				rc = munmap(align_lp(tcpu->b[j][k], page_sz(tcfg)),
					page_align_sz(tcfg, tcfg->blen));
				if (rc)
					ERR("Error in munmap %s %p\n", strerror(errno),  tcpu->b[j][k]);
			}
		}
	}

	for (i = 0; i < tcfg->nb_numa_node; i++) {
		struct numa_mem *nm = &tcfg->numa_mem[i];

		if (!nm->desc_comp)
			continue;

		rc = munmap(align_lp(nm->desc_comp, page_sz(tcfg)),
			page_align_sz(tcfg, numa_node_desc_comp_size(tcfg, i)));
		if (rc)
			ERR("Error in munmap %s %p\n", strerror(errno),  nm->desc_comp);
	}

}

void
test_free(struct tcfg *tcfg)
{
	unsigned int i;
	struct tcfg_cpu *tcpu;
	int rc;

	if (!tcfg->large_stride) {
		for (i = 0; i < tcfg->nb_numa_node; i++) {
			if (tcfg->numa_mem[i].sz == 0)
				continue;
			rc = munmap(tcfg->numa_mem[i].base_addr,
				page_align_sz(tcfg, tcfg->numa_mem[i].sz));
			if (rc)
				ERR("Error in munmap: %s %lu\n", strerror(errno),
				tcfg->numa_mem[i].sz);
		}
	} else
		test_do_sparse_munmap(tcfg);

	for (i = 0; tcfg->op_info && i < tcfg->op_info->nb_buf; i++) {
		if (tcfg->mmio_mem[i].sz == 0)
			continue;
		rc = munmap(tcfg->mmio_mem[i].base_addr, tcfg->mmio_mem[i].sz);
		if (rc)
			ERR("Error in munmap: %s %lu\n", strerror(errno),
			tcfg->mmio_mem[i].sz);

		free(tcfg->mmio_mem[i].bfile);
	}

	if (tcfg->id_owner_info) {
		for (i = 0; i < tcfg->id_nb_owners; i++) {
			if (tcfg->id_owners_given)
				free(tcfg->id_owners[i].d);
			close(tcfg->id_owner_info[i].wq_fd);
			munmap(tcfg->id_owner_info[i].idpte_fd, tcfg->id_window_cnt * sizeof(int));
			munmap(tcfg->id_owner_info[i].sub_idx, tcfg->nb_cpus * sizeof(int));
		}
		munmap(tcfg->id_owner_info, tcfg->id_nb_owners * sizeof(struct id_owner_info));
	}
	free(tcfg->id_owners);

	if (tcfg->tcpu) {

		free_buf_addr_array(tcfg);

		for (i = 0; i < tcfg->nb_cpus; i++) {
			tcpu = &tcfg->tcpu[i];
			test_free_op_priv(tcpu);
			free(tcpu->dname);
			close(tcpu->wq_fd);

		}
		rc = munmap(tcfg->tcpu, tcfg->nb_cpus * sizeof(*tcfg->tcpu));
		if (rc)
			ERR("Error in munmap: %s\n", strerror(errno));
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

	err = test_init_inter_domain_global(tcfg);
	if (err)
		return err;

	return 0;
}
