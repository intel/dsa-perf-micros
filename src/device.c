// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <accel-config/libaccel_config.h>
#include <string.h>
#include <search.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "common.h"
#include "dsa.h"
#include "device.h"
#include "idxd_device.h"
#include "user_device.h"

static int dd;

void *
wq_map(char *dname, int wq_id, int shared, int numa_node)
{
	void *ptr = NULL;

	switch (dd) {

	case IDXD:
		ptr = idxd_wq_get(dname, wq_id, shared, numa_node);
		break;

	case USER:
		ptr = ud_wq_get(dname, wq_id, shared, numa_node);
		break;

	default:
		ERR("Unknown wq type %d\n", dd);
	}

	return ptr;
}

void
wq_unmap(void *ptr)
{
	switch (dd) {

	case IDXD:
		idxd_wq_unmap(ptr);
		break;

	case USER:
		ud_wq_unmap(ptr);
		break;

	default:
		ERR("Unknown wq type %d\n", dd);
	}
}

void
wq_info_get(void *wq, struct wq_info *wq_info)
{
	switch (dd) {

	case IDXD:
		idxd_wq_info_get(wq, wq_info);
		break;

	case USER:
		ud_wq_info_get(wq, wq_info);
		break;

	default:
		ERR("Unknown wq type %d\n", dd);
	}
}

int
dmap(int fd, void *va, ssize_t len)
{
	if (fd != -1)
		return ud_dmap(fd, va, len);
	return 0;
}

int
dunmap(int fd, void *va, ssize_t len)
{
	if (fd != -1)
		return ud_dunmap(fd, va, len);
	return 0;
}

int
iommu_disabled(void)
{
	return dd == USER && ud_iommu_disabled();
}

int
driver_init(struct tcfg *tcfg)
{
	int rc;

	rc = 0;
	dd = tcfg->driver;
	if (dd == USER)
		rc = user_driver_init(tcfg);

	return rc;
}

uint64_t rte_mem_virt2iova(void *p)
{
	return dd == IDXD ? (uint64_t)p : user_virt2iova(p);
}
