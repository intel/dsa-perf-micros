// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stddef.h>
#include <search.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <accel-config/libaccel_config.h>

#include "common.h"
#include "dsa.h"
#include "device.h"
#include "idxd_device.h"

struct idxd_wq_info {
	void *ptr;
	void *ctx;
	void *wq;
};

#define WQ_NUM_MAX 128
static struct idxd_wq_info idxd_wqi_arr[WQ_NUM_MAX];

static int
cmp(const void *p1, const void *p2)
{
	const struct idxd_wq_info *wqi = p2;

	return wqi->ptr == p1 ? 0 : 1;
}

static struct idxd_wq_info *
wqi_alloc(void)
{
	size_t n = ARRAY_SIZE(idxd_wqi_arr);

	return lfind(NULL, idxd_wqi_arr, &n, sizeof(*idxd_wqi_arr), cmp);
}

static void
wqi_free(void *ptr)
{
	struct idxd_wq_info *wqi;
	size_t n = ARRAY_SIZE(idxd_wqi_arr);

	wqi = lfind(ptr, idxd_wqi_arr, &n, sizeof(*idxd_wqi_arr), cmp);
	if (wqi)
		wqi->ptr = NULL;
}

static int
open_wq(struct accfg_wq *wq)
{
	int fd;
	char path[PATH_MAX];
	int rc;

	rc = accfg_wq_get_user_dev_path(wq, path, sizeof(path));
	if (rc)
		return rc;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		ERR("File open error %s: %s\n", path, strerror(errno));
		return -1;
	}

	return fd;
}


static struct accfg_wq *
idxd_wq_find(struct accfg_ctx *ctx, char *dname, int wq_id, int shared, int numa_node)
{
	struct accfg_device *device;
	struct accfg_wq *wq;

	accfg_device_foreach(ctx, device) {
		enum accfg_device_state dstate;
		int fd;

		/* Make sure that the device is enabled */
		dstate = accfg_device_get_state(device);
		if (dstate != ACCFG_DEVICE_ENABLED)
			continue;

		/* Match the device to the id requested */
		if (dname && strcmp(accfg_device_get_devname(device), dname))
			continue;

		if ((!dname && accfg_device_get_numa_node(device) != -1) &&
			(numa_node != accfg_device_get_numa_node(device)))
			continue;

		accfg_wq_foreach(device, wq) {
			enum accfg_wq_state wstate;
			enum accfg_wq_type type;

			if (wq_id != -1 && accfg_wq_get_id(wq) != wq_id)
				continue;

			/* Get a workqueue that's enabled */
			wstate = accfg_wq_get_state(wq);
			if (wstate != ACCFG_WQ_ENABLED)
				continue;

			/* The wq type should be user */
			type = accfg_wq_get_type(wq);
			if (type != ACCFG_WQT_USER)
				continue;

			/* Make sure the mode is correct */
			if (wq_id == -1) {
				int mode = accfg_wq_get_mode(wq);

				if ((mode == ACCFG_WQ_SHARED && !shared)
					|| (mode == ACCFG_WQ_DEDICATED && shared))
					continue;
			}

			fd = open_wq(wq);
			if (fd < 0)
				continue;

			close(fd);
			return wq;
		}
	}

	return NULL;
}
static void *
idxd_wq_mmap(struct accfg_wq *wq)
{
	int fd;
	void *wq_reg;

	fd = open_wq(wq);

	wq_reg = mmap(NULL, 0x1000, PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
	if (wq_reg == MAP_FAILED) {
		ERR("mmap error: %s", strerror(errno));
		close(fd);
		return NULL;
	}

	close(fd);
	return wq_reg;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *
idxd_wq_get(char *dname, int wq_id, int shared, int numa_node)
{
	struct accfg_ctx *ctx;
	struct accfg_wq *wq;
	struct idxd_wq_info *wqi;
	void *ptr;

	pthread_mutex_lock(&lock);

	accfg_new(&ctx);

	wqi = wqi_alloc();

	wq = idxd_wq_find(ctx, dname, wq_id, shared, numa_node);
	if (wq == NULL) {
		ERR("Failed to find a WQ\n");
		goto err_ret;
	}

	ptr = idxd_wq_mmap(wq);
	if (!ptr) {
		ERR("Failed to map WQ dev %s wq %d\n", dname,
			accfg_wq_get_id(wq));
		goto err_ret;
	}

	pthread_mutex_unlock(&lock);

	wqi->wq = wq;
	wqi->ptr = ptr;
	wqi->ctx = ctx;

	return ptr;

 err_ret:
	pthread_mutex_unlock(&lock);
	accfg_unref(ctx);
	return NULL;
}

void
idxd_wq_info_get(void *ptr, struct wq_info *wq_info)
{
	struct idxd_wq_info *wqi;
	size_t n = ARRAY_SIZE(idxd_wqi_arr);

	wqi = lfind(ptr, idxd_wqi_arr, &n, sizeof(*idxd_wqi_arr), cmp);

	wq_info->size = accfg_wq_get_size(wqi->wq);
	wq_info->dmap_fd = -1;
	wq_info->dname = accfg_device_get_devname(accfg_wq_get_device(wqi->wq));
	wq_info->dwq = accfg_wq_get_mode(wqi->wq) == ACCFG_WQ_DEDICATED;
	wq_info->dev_type = accfg_device_get_type(accfg_wq_get_device(wqi->wq))
				== ACCFG_DEVICE_DSA ? DSA : IAX;
}

void
idxd_wq_unmap(void *wq)
{
	struct idxd_wq_info *wqi;
	size_t n = ARRAY_SIZE(idxd_wqi_arr);

	pthread_mutex_lock(&lock);

	wqi = lfind(wq, idxd_wqi_arr, &n, sizeof(*idxd_wqi_arr), cmp);
	wqi_free(wqi);
	munmap(wq, 0x1000);
	accfg_unref(wqi->ctx);

	pthread_mutex_unlock(&lock);
}
