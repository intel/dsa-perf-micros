// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/pci_regs.h>
#include <dlfcn.h>
#include <linux/ioctl.h>
#include <linux/vfio.h>
#include <search.h>

#include "common.h"
#include "device.h"
#include "user_device.h"

#define MAP_SIZE (1UL * 1024 * 1024 * 1024)
#define MAP_CHUNK (4 * 1024)
#define REALLOC_INTERVAL 30
#define PORTAL_SIZE (4 * 1024)

/* used to limit udev count for klockworks error message */
#define MAX_USER_DEVICE (8 * 8)

#define __rte_aligned(a)   __attribute__((__aligned__(a)))
#define	__rte_cache_aligned   __rte_aligned(64)

#define RTE_PTR_ADD(p, a) ((void *)((uintptr_t)(p) + (a)))

static int nb_udev;
static int nb_wq;

struct udev_info {
	char *bdf;
	short dev_id;
	void *udev_ctx;
	struct idxd_pci_common *pci;
	int dmap_fd;
	int wq_avail;
	int nb_wq;
	unsigned int nb_engines;
	int numa_node;
	uint64_t resource[2];
	bool init_done;
};

static struct udev_info *udi;

struct ud_wq_info {
	void *ptr;
	int wq_id;
	struct udev_info *udi;
};

static struct ud_wq_info *uwi;
static int uio_cnt, vfio_cnt;

#define WQ_NUM_MAX 128

struct rte_idxd_version {
	uint32_t	minor:8;
	uint32_t	major:8;
	uint32_t	rsvd:16;
};

/* General bar0 registers */
struct rte_idxd_bar0 {
	struct rte_idxd_version __rte_cache_aligned version;    /* offset 0x00 */
	uint64_t __rte_aligned(0x10) gencap;                    /* offset 0x10 */
	uint64_t __rte_aligned(0x10) wqcap;                     /* offset 0x20 */
	uint64_t __rte_aligned(0x10) grpcap;                    /* offset 0x30 */
	uint64_t __rte_aligned(0x08) engcap;                    /* offset 0x38 */
	uint64_t __rte_aligned(0x10) opcap;                     /* offset 0x40 */
	uint64_t __rte_aligned(0x20) offsets[2];                /* offset 0x60 */
	uint32_t __rte_aligned(0x20) gencfg;                    /* offset 0x80 */
	uint32_t __rte_aligned(0x08) genctrl;                   /* offset 0x88 */
	uint32_t __rte_aligned(0x10) gensts;                    /* offset 0x90 */
	uint32_t __rte_aligned(0x08) intcause;                  /* offset 0x98 */
	uint32_t __rte_aligned(0x10) cmd;                       /* offset 0xA0 */
	uint32_t __rte_aligned(0x08) cmdstatus;                 /* offset 0xA8 */
	uint64_t __rte_aligned(0x20) swerror[4];                /* offset 0xC0 */
};

/* workqueue config is provided by array of uint32_t. */
#define WQ_SIZE_IDX      0 /* size is in first 32-bit value */
#define WQ_THRESHOLD_IDX 1 /* WQ threshold second 32-bits */
#define WQ_MODE_IDX      2 /* WQ mode and other flags */
#define WQ_SIZES_IDX     3 /* WQ transfer and batch sizes */
#define WQ_OCC_INT_IDX   4 /* WQ occupancy interrupt handle */
#define WQ_OCC_LIMIT_IDX 5 /* WQ occupancy limit */
#define WQ_STATE_IDX     6 /* WQ state and occupancy state */

#define WQ_MODE_SHARED    0
#define WQ_MODE_DEDICATED 1
#define WQ_PRIORITY_SHIFT 4
#define WQ_BATCH_SZ_SHIFT 5
#define WQ_STATE_SHIFT 30
#define WQ_STATE_MASK 0x3

struct rte_idxd_grpflags {
	union {
		struct {
			uint64_t	tc_a:3;
			uint64_t	tc_b:3;
			uint64_t	rsvd1:1;
			uint64_t	rdbflimit:1;
			uint64_t	rdbfrsvd:8;
			uint64_t	rsvd2:4;
			uint64_t	rdbfalwd:8;
			uint64_t	rsvd3:4;
			uint64_t	workdescinproglimit:2;
			uint64_t	rsvd4:2;
			uint64_t	batchdescinproglimit:2;
			uint64_t	rsvd5:26;
		};
		uint64_t value;
	};
};

struct rte_idxd_grpcfg {
	uint64_t grpwqcfg[4]  __rte_cache_aligned; /* 64-byte register set */
	uint64_t grpengcfg;                        /* offset 32 */
	struct rte_idxd_grpflags grpflags;         /* offset 40 */
};

#define GENSTS_DEV_STATE_MASK 0x03
#define CMDSTATUS_ACTIVE_SHIFT 31
#define CMDSTATUS_ACTIVE_MASK (1 << 31)
#define CMDSTATUS_ERR_MASK 0xFF
#define IDXD_CMD_SHIFT 20

enum rte_idxd_cmds {
	idxd_enable_dev = 1,
	idxd_disable_dev,
	idxd_drain_all,
	idxd_abort_all,
	idxd_reset_device,
	idxd_enable_wq,
	idxd_disable_wq,
	idxd_drain_wq,
	idxd_abort_wq,
	idxd_reset_wq,
};

struct idxd_pci_common {
	uint8_t wq_cfg_sz;
	volatile struct rte_idxd_bar0 *regs;
	volatile uint32_t *wq_regs_base;
	volatile struct rte_idxd_grpcfg *grp_regs;
	volatile void *portals;
};

const int max_queues = 1;

static inline int
idxd_pci_dev_command(struct idxd_pci_common *pci, enum rte_idxd_cmds command)
{
	uint8_t err_code;
	uint16_t qid = 0;
	int i = 0;

	if (command >= idxd_disable_wq && command <= idxd_reset_wq)
		qid = (1 << qid);

	pci->regs->cmd = (command << IDXD_CMD_SHIFT) | qid;

	do {
		__builtin_ia32_pause();
		err_code = pci->regs->cmdstatus;
		if (++i >= 1000) {
			ERR("Timeout waiting for command response from HW");
			return err_code;
		}
	} while (pci->regs->cmdstatus & CMDSTATUS_ACTIVE_MASK);

	return err_code & CMDSTATUS_ERR_MASK;
}

static uint32_t *
idxd_get_wq_cfg(struct idxd_pci_common *pci, uint8_t wq_idx)
{
	return RTE_PTR_ADD(pci->wq_regs_base,
			(uintptr_t)wq_idx << (5 + pci->wq_cfg_sz));
}

static int
pci_uio_set_bus_master(int dev_fd)
{
	uint16_t reg;
	int rc;

	rc = pread(dev_fd, &reg, sizeof(reg), PCI_COMMAND);
	if (rc != sizeof(reg)) {
		ERR("Cannot read command from PCI config space!\n");
		return -EIO;
	}

	/* return if bus mastering is already on */
	if (reg & PCI_COMMAND_MASTER) {
		INFO("Bus master already enabled\n");
		return 0;
	}

	reg |= PCI_COMMAND_MASTER;

	rc = pwrite(dev_fd, &reg, sizeof(reg), PCI_COMMAND);
	if (rc != sizeof(reg)) {
		ERR("Cannot write command to PCI config space!\n");
		return -EIO;
	}

	return 0;
}

/* enable PCI bus memory space */
static int
pci_vfio_enable_bus_memory(int dev_fd)
{
	uint16_t cmd;
	int rc;

#define VFIO_GET_REGION_ADDR(x) ((uint64_t) x << 40ULL)

	rc = pread(dev_fd, &cmd, sizeof(cmd),
		      VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) +
		      PCI_COMMAND);

	if (rc != sizeof(cmd)) {
		ERR("Cannot read command from PCI config space!\n");
		return -EIO;
	}

	if (cmd & PCI_COMMAND_MEMORY)
		return 0;

	cmd |= PCI_COMMAND_MEMORY;
	rc = pwrite(dev_fd, &cmd, sizeof(cmd),
		       VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) +
		       PCI_COMMAND);

	if (rc != sizeof(cmd)) {
		ERR("Cannot write command to PCI config space!\n");
		return -EIO;
	}

	return 0;
}

static int
exec_cmd(char *cmd, uint32_t *v)
{
	FILE *fp;
	int rc;

	fp = popen(cmd, "r");
	if (!fp) {
		ERR("popen failed\n");
		return -1;
	}

	rc = v ? fscanf(fp, "%x", v)  == 1 ? 0 : -1 : 0;
	pclose(fp);

	return rc;
}

#define TPH_CTL "168"

static int
read_tph(char *bdf, uint32_t *tph)
{
	char *cmd;
	int rc;

	rc = asprintf(&cmd, "setpci -s %s "TPH_CTL".l", bdf);
	if (rc < 0)
		return -1;
	rc = exec_cmd(cmd, tph);
	free(cmd);

	return rc;
}

static int
write_tph(char *bdf, int32_t v)
{
	char *cmd;
	int rc;

	rc = asprintf(&cmd, "setpci -s %s "TPH_CTL".l=0x%x", bdf, v);
	if (rc < 0)
		return -1;

	rc = exec_cmd(cmd, NULL);
	free(cmd);

	return rc;
}

static int
uio_setup_device(char *bdf)
{
	char *cmd;
	FILE *fp;
	int fd;
	int rc;
	char *uio_name;
	char *uio_cfg_name;
	char *reset_cmd;

	rc = asprintf(&cmd, "basename `ls -d  /sys/bus/pci/devices/%s/uio/uio*`",
		bdf);
	if (rc == 0 || rc == -1) {
		free(cmd);
		ERR("Failed in asprintf\n");
		return -ENOMEM;
	}

	fp = popen(cmd, "r");
	if (!fp) {
		ERR("Failed in popen(%s)\n", cmd);
		free(cmd);
		return -EIO;
	}

	free(cmd);
	rc = fscanf(fp, "%m[^\n]", &uio_name);
	pclose(fp);
	if (rc == 0 || rc == -1) {
		ERR("Failed in fscanf\n");
		return -EIO;
	}

	rc = asprintf(&reset_cmd, "echo 1 > /sys/bus/pci/devices/%s/reset", bdf);
	if (rc == 0 || rc == -1) {
		ERR("Failed in asprintf\n");
		free(reset_cmd);
		return -ENOMEM;
	}

	rc = system(reset_cmd);
	if (rc == -1) {
		ERR("error in resetting device cmd %s\n", reset_cmd);
		free(reset_cmd);
		return -EIO;
	}

	free(reset_cmd);
	rc = asprintf(&uio_cfg_name, "/sys/class/uio/%s/device/config", uio_name);
	free(uio_name);
	if (rc == 0 || rc == -1) {
		ERR("Error in asprintf\n");
		free(uio_cfg_name);
		return -ENOMEM;
	}

	fd = open(uio_cfg_name, O_RDWR);
	free(uio_cfg_name);
	if (fd == -1) {
		ERR("Error in open: %s\n", strerror(errno));
		return -errno;
	}

	pci_uio_set_bus_master(fd);

	close(fd);

	return 0;
}

/* set PCI bus mastering */
static int
pci_vfio_set_bus_master(int dev_fd, bool op)
{
	uint16_t reg;
	int rc;

	rc = pread(dev_fd, &reg, sizeof(reg),
			VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) +
			PCI_COMMAND);
	if (rc != sizeof(reg)) {
		ERR("Cannot read command from PCI config space!\n");
		return -EIO;
	}

	if (op)
		/* set the master bit */
		reg |= PCI_COMMAND_MASTER;
	else
		reg &= ~(PCI_COMMAND_MASTER);

	rc = pwrite(dev_fd, &reg, sizeof(reg),
			VFIO_GET_REGION_ADDR(VFIO_PCI_CONFIG_REGION_INDEX) +
			PCI_COMMAND);

	if (rc != sizeof(reg)) {
		ERR("Cannot write command to PCI config space!\n");
		return -EIO;
	}

	return 0;
}

static int
vfio_setup_device(int vfio_dev_fd)
{
	if (pci_vfio_enable_bus_memory(vfio_dev_fd)) {
		ERR("Cannot enable bus memory!\n");
		return -EIO;
	}

	/* set bus mastering for the device */
	if (pci_vfio_set_bus_master(vfio_dev_fd, true)) {
		ERR("Cannot set up bus mastering!\n");
		return -EIO;
	}

	/*
	 * Reset the device. If the device is not capable of resetting,
	 * then it updates errno as EINVAL.
	 */
	if (ioctl(vfio_dev_fd, VFIO_DEVICE_RESET) && errno != EINVAL) {

		ERR("Unable to reset device! Error: %d (%s)\n",
				errno, strerror(errno));
		return -errno;
	}

	return 0;
}

static int
init_pci_device(struct udev_info *udi, uint64_t resource[1])
{
	struct idxd_pci_common *pci;
	uint8_t nb_groups, nb_engines, nb_wqs;
	uint16_t grp_offset, wq_offset; /* how far into bar0 the regs are */
	uint16_t wq_size, total_wq_size;
	uint8_t lg2_max_batch, lg2_max_copy_size;
	unsigned int i, err_code;
	int rc;

	INFO("Enabling bdf %s\n", udi->bdf);

	pci = malloc(sizeof(*pci));
	if (pci == NULL) {
		ERR("Can't allocate memory");
		return -ENOMEM;
	}

	/* assign the bar registers, and then configure device */
	pci->regs = (volatile struct rte_idxd_bar0 *)resource[0];
	grp_offset = (uint16_t)pci->regs->offsets[0];
	pci->grp_regs = RTE_PTR_ADD(pci->regs, grp_offset * 0x100);
	wq_offset = (uint16_t)(pci->regs->offsets[0] >> 16);
	pci->wq_regs_base = RTE_PTR_ADD(pci->regs, wq_offset * 0x100);
	pci->wq_cfg_sz = (pci->regs->wqcap >> 24) & 0x0F;

	/* sanity check device status */
	if (pci->regs->gensts & GENSTS_DEV_STATE_MASK) {
		/* need function-level-reset (FLR) or is enabled */
		ERR("Device status is not disabled, cannot init");
		rc = -errno;
		goto err;
	}
	if (pci->regs->cmdstatus & CMDSTATUS_ACTIVE_MASK) {
		/* command in progress */
		ERR("Device has a command in progress, cannot init");
		rc = -errno;
		goto err;
	}

	/* read basic info about the hardware for use when configuring */
	nb_groups = (uint8_t)pci->regs->grpcap;
	nb_engines = (uint8_t)pci->regs->engcap;
	nb_wqs = (uint8_t)(pci->regs->wqcap >> 16);
	total_wq_size = (uint16_t)pci->regs->wqcap;
	lg2_max_copy_size = (uint8_t)(pci->regs->gencap >> 16) & 0x1F;
	lg2_max_batch = (uint8_t)(pci->regs->gencap >> 21) & 0x0F;

	INFO("nb_groups = %u, nb_engines = %u, nb_wqs = %u\n",
			nb_groups, nb_engines, nb_wqs);

	/* zero out any old config */
	for (i = 0; i < nb_groups; i++) {
		pci->grp_regs[i].grpengcfg = 0;
		pci->grp_regs[i].grpwqcfg[0] = 0;

		/* use tc1 for best performance on spr/gnr*/
		if (pci->regs->version.major <= 2) {
			pci->grp_regs[0].grpflags.tc_a = 1;
			pci->grp_regs[0].grpflags.tc_b = 1;
		}
	}
	for (i = 0; i < nb_wqs; i++)
		idxd_get_wq_cfg(pci, i)[0] = 0;

	/* limit queues if necessary */
	if (max_queues != 0 && nb_wqs > max_queues) {
		nb_wqs = max_queues;
		INFO("Limiting queues to %u\n", nb_wqs);
	}

	for (i = 0; i < nb_engines && i < udi->nb_engines; i++) {
		INFO("Assigning engine %u to group %u\n",
				i, 0);
		pci->grp_regs[0].grpengcfg |= (1ULL << i);
	}

	/* now do the same for queues and give work slots to each queue */
	wq_size = total_wq_size / nb_wqs;
	INFO("Work queue size = %u, max batch = 2^%u, max copy = 2^%u\n",
			wq_size, lg2_max_batch, lg2_max_copy_size);

	for (i = 0; i < nb_wqs; i++) {
		/* add engine "i" to a group */
		INFO("Assigning work queue %u to group %u\n",
				i, i % nb_groups);
		pci->grp_regs[i % nb_groups].grpwqcfg[0] |= (1ULL << i);
		/* now configure it, in terms of size, max batch, mode */
		idxd_get_wq_cfg(pci, i)[WQ_SIZE_IDX] = wq_size;
		idxd_get_wq_cfg(pci, i)[WQ_MODE_IDX] = (1 << WQ_PRIORITY_SHIFT) |
				WQ_MODE_DEDICATED;
		idxd_get_wq_cfg(pci, i)[WQ_SIZES_IDX] = lg2_max_copy_size |
				(lg2_max_batch << WQ_BATCH_SZ_SHIFT);
	}

	/* dump the group configuration to output */
	for (i = 0; i < nb_groups; i++) {
		INFO("## Group %d", i);
		INFO("    GRPWQCFG: %"PRIx64"\n", pci->grp_regs[i].grpwqcfg[0]);
		INFO("    GRPENGCFG: %"PRIx64"\n", pci->grp_regs[i].grpengcfg);
		INFO("    GRPFLAGS: %"PRIx64"\n", pci->grp_regs[i].grpflags.value);
	}

	/* enable the device itself */
	err_code = idxd_pci_dev_command(pci, idxd_enable_dev);
	if (err_code) {
		ERR("Error enabling device: code %#x", err_code);
		rc = -EIO;
		goto err;
	}

	INFO("IDXD Device enabled OK\n");
	udi->pci = pci;

	return 0;

err:
	free(pci);
	return rc;
}

static int
uio_dev_busy(char *bdf)
{
	char *cmd = NULL;
	FILE *fp = NULL;
	int rc;
	int cnt;

	rc = asprintf(&cmd, "which lsof | wc -l");
	if (rc == -1) {
		ERR("unable to locate lsof - multi-instance will not work\n");
		goto err_busy;
	}

	fp = popen(cmd, "r");
	if (fp == NULL) {
		ERR("Unable to read from %s\n", cmd);
		ERR("multi-instance will not work\n");
		goto err_busy;
	}

	rc = fscanf(fp, "%d", &cnt);
	if (rc == 0 || rc == -1) {
		ERR("unable to locate lsof - multi-instance support will not work\n");
		goto err_busy;
	}

	pclose(fp);
	fp = NULL;
	free(cmd);
	cmd = NULL;
	rc = asprintf(&cmd, "lsof -t /sys/bus/pci/devices/%s/resource0 | wc -l", bdf);
	if (rc == -1) {
		ERR("Unable to form cmd\n");
		ERR("unable to run lsof - multi-instance support will not work\n");
		goto err_busy;
	}

	fp = popen(cmd, "r");
	if (fp == NULL) {
		ERR("Unable to read from cmd %s, multi-instance will not work\n", cmd);
		goto err_busy;
	}
	rc = fscanf(fp, "%d", &cnt);
	if (rc == 0 || rc == -1) {
		ERR("Unable to read from cmd %s, multi-instance will not work\n", cmd);
		goto err_busy;
	}

	pclose(fp);
	free(cmd);

	return rc == 1 ? cnt != 0 : 0;

 err_busy:
	if (fp)
		pclose(fp);
	if (cmd)
		free(cmd);
	return 0;
}

static uint64_t
uio_map(char *bdf, const char *resource)
{
	char *path;
	int fd;
	void *ptr;
	int rc;

	rc = asprintf(&path, "/sys/bus/pci/devices/%s/%s", bdf, resource);
	if (rc == -1) {
		free(path);
		return (uintptr_t) NULL;
	}

	fd = open(path, O_RDWR);
	free(path);
	if (fd == -1) {
		ERR("open %s failed\n", strerror(errno));
		return (uintptr_t) NULL;
	}

	ptr = mmap(NULL, PORTAL_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		ERR("mmap failed: %s\n", strerror(errno));
		ptr = NULL;
	}

	close(fd);

	return (uintptr_t) ptr;
}

static
int pci_dev_id(char *bdf)
{
	int rc;
	char *path;
	int fd;
	char buf[80];
	unsigned long  didl;

	rc = asprintf(&path, "/sys/bus/pci/devices/%s/device", bdf);
	if (rc == 0 || rc == -1) {
		ERR("Unable to construct path\n");
		free(path);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		ERR("open %s failed: %s\n", path, strerror(errno));
		free(path);
		return -errno;
	}

	free(path);
	rc = read(fd, buf, sizeof(buf));
	if (rc < 0) {
		rc = -errno;
		ERR("read failed: %s\n", strerror(errno));
		close(fd);
		return rc;
	}

	close(fd);

	didl = strtoul(buf, NULL, 16);
	if (didl == ULONG_MAX)
		return -errno;

	return (int)didl;
}

static int
uio_init(struct udev_info *udi)
{
	int rc;

	if (uio_dev_busy(udi->bdf))
		return -EBUSY;

	udi->resource[0] = uio_map(udi->bdf, "resource0");
	udi->resource[1] = uio_map(udi->bdf, "resource2");

	rc = uio_setup_device(udi->bdf);
	if (rc)
		return rc;

	rc = init_pci_device(udi, &udi->resource[0]);
	if (rc)
		return rc;

	udi->dmap_fd = -1;
	rc = pci_dev_id(udi->bdf);
	if (rc < 0)
		return rc;

	udi->dev_id = (short)rc;

	return 0;
}

static int
vfio_init(struct udev_info *udi)
{
	char *bdf;
	int len;
	uint seg, bus, slot, func;
	int rc, container, group, groupid;
	char path[50], iommu_group_path[50], *group_name;
	struct stat st;
	int i;
	uint64_t resource[2] = {0};
	int region_id[2];

	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status)
	};
	struct vfio_device_info device_info = {
		.argsz = sizeof(device_info)
	};
	struct vfio_region_info region_info = {
		.argsz = sizeof(region_info)
	};
	int device;

	bdf = udi->bdf;
	region_id[0] = 0;
	region_id[1] = 2;

	/* Boilerplate vfio setup */
	rc = sscanf(bdf, "%04x:%02x:%02x.%x", &seg, &bus, &slot, &func);
	if (rc != 4) {
		ERR("BDF string construction failed\n");
		return -ENOMEM;
	}

	container = open("/dev/vfio/vfio", O_RDWR);
	if (container < 0) {
		ERR("Failed to open /dev/vfio/vfio, %d (%s)\n",
		       container, strerror(errno));
		return -errno;
	}

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/",
		 seg, bus, slot, func);

	rc = stat(path, &st);
	if (rc < 0) {
		ERR("No such device: %s\n", strerror(errno));
		close(container);
		return  -errno;
	}

	memmove(path + strlen(path), "iommu_group",
		min(sizeof(path) - strlen(path), sizeof("iommu_group")));

	len = readlink(path, iommu_group_path, sizeof(iommu_group_path));
	if (len <= 0) {
		close(container);
		ERR("No iommu_group for device: %s, path %s\n", strerror(errno), path);
		return -errno;
	}

	iommu_group_path[len] = 0;
	group_name = basename(iommu_group_path);

	if (sscanf(group_name, "%d", &groupid) != 1) {
		close(container);
		ERR("Unknown group %s\n", group_name);
		return -EIO;
	}

	snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
	group = open(path, O_RDWR);
	if (group < 0) {
		rc = -errno;
		ERR("Failed to open %s, %d (%s)\n", path, group, strerror(errno));
		close(container);
		return rc;
	}

	rc = ioctl(group, VFIO_GROUP_GET_STATUS, &group_status);
	if (rc) {
		rc = -errno;
		ERR("ioctl(VFIO_GROUP_GET_STATUS) failed: %s\n", strerror(errno));
		close(group);
		close(container);
		return rc;
	}

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		close(group);
		close(container);
		ERR("Group not viable, are all devices attached to vfio?\n");
		return -EINVAL;
	}

	rc = ioctl(group, VFIO_GROUP_SET_CONTAINER, &container);
	if (rc) {
		rc = -errno;
		ERR("Failed to set group container: %s\n", strerror(errno));
		close(group);
		close(container);
		return rc;
	}

	rc = ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
	if (rc) {
		rc = -errno;
		ERR("Failed to set IOMMU: %s\n", strerror(errno));
		close(group);
		close(container);
		return rc;
	}

	snprintf(path, sizeof(path), "%04x:%02x:%02x.%d", seg, bus, slot, func);

	device = ioctl(group, VFIO_GROUP_GET_DEVICE_FD, path);
	if (device < 0) {
		rc = -errno;
		ERR("Failed to get device %s:%s\n", path, strerror(errno));
		close(group);
		close(container);
		return rc;
	}

	rc = ioctl(device, VFIO_DEVICE_GET_INFO, &device_info);
	if (rc) {
		rc = -errno;
		ERR("Failed to get device info: %s\n", strerror(errno));
		close(group);
		close(container);
		return rc;
	}

	INFO("Device supports %d regions, %d irqs\n",
	       device_info.num_regions, device_info.num_irqs);

	INFO("size 0x%lx, offset 0x%lx, flags 0x%x\n",
		       (unsigned long)region_info.size,
		       (unsigned long)region_info.offset, region_info.flags);

	rc = 0;
	for (i = 0; i < ARRAY_SIZE(region_id); i++) {
		INFO("Region %d: ", region_id[i]);

		region_info.index = region_id[i];

		rc = ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &region_info);
		if (rc) {
			rc = -errno;
			ERR("Failed to get info: %s\n", strerror(errno));
			break;
		}

		INFO("size 0x%lx, offset 0x%lx, flags 0x%x\n",
		       (unsigned long)region_info.size,
		       (unsigned long)region_info.offset, region_info.flags);

		resource[i]  = (uint64_t)mmap(NULL, (size_t)region_info.size,
					 PROT_READ | PROT_WRITE, MAP_SHARED, device,
					 (off_t)region_info.offset);
		if (resource[i] == (uintptr_t)MAP_FAILED) {
			rc = -errno;
			ERR("mmap failedi: %s\n", strerror(errno));
			break;
		}
	}

	close(group);

	if (rc) {
		close(container);
		return rc;
	}

	rc = vfio_setup_device(device);
	if (rc) {
		close(container);
		return rc;
	}

	rc = init_pci_device(udi, &resource[0]);
	if (rc) {
		close(container);
		return rc;
	}

	udi->resource[0] = resource[0];
	udi->resource[1] = resource[1];
	udi->dmap_fd = container;

	return 0;
}

int ud_dmap(int container, void *va, ssize_t len)
{
	int rc;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map)
	};

	/* Test code */
	dma_map.argsz = sizeof(struct vfio_iommu_type1_dma_map);
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
	dma_map.size = len;
	dma_map.iova = (unsigned long)va;
	dma_map.vaddr = (unsigned long)va;

	rc = ioctl(container, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (rc) {
		rc = -errno;
		ERR("Failed to map memory (%s)\n", strerror(errno));
		return rc;
	}

	return 0;
}

int ud_dunmap(int container, void *va, ssize_t len)
{
	int rc;

	struct vfio_iommu_type1_dma_unmap dma_unmap = {
		.argsz = sizeof(dma_unmap)
	};

	dma_unmap.iova = (uintptr_t)va;
	dma_unmap.size = len;

	rc = ioctl(container, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	if (rc) {
		rc = -errno;
		ERR("Failed to unmap memory (%s)\n", strerror(errno));
		return rc;
	}

	return rc;
}

static int
udev_count(const char *cmd)
{
	FILE *fp;
	int cnt;
	int rc;

	fp = popen(cmd, "r");
	if (!fp)
		return 0;

	cnt = 0;
	rc = fscanf(fp, "%d", &cnt);
	pclose(fp);

	if (cnt > MAX_USER_DEVICE)
		return 0;

	return rc == 0 || rc == -1 ? 0 : cnt;
}

#define COUNT_CMD(f) \
	"[ -e /sys/bus/pci/drivers/"#f" ] &&"\
	"[ `find /sys/bus/pci/drivers/"#f"/ -type l ! -name module | wc -l` -gt \"0\" ] && "\
	"find /sys/bus/pci/drivers/"#f"/ -type l ! -name module | wc -l"

static int
vfio_dev_count(void)
{
	return	udev_count(COUNT_CMD(vfio-pci));
}

static int
uio_dev_count(void)
{
	return udev_count(COUNT_CMD(uio_pci_generic));
}

#define BDF_CMD(f) \
	"for f in `find /sys/bus/pci/drivers/"#f"/ -type l ! -name module`; do "\
	"basename $f; done"

static void* (*rte_malloc_socket)(const char *type, size_t size, unsigned int align, int node);

static void *phys_malloc(size_t size, unsigned int align, int node)
{
	return rte_malloc_socket ?
		rte_malloc_socket(NULL, size, align,
				node == -1 ? node_id() : node) : 0;
}

static const char *eal_loc[] = {
		"/usr/lib/x86_64-linux-gnu/librte_eal.so",
		"/lib64/librte_eal.so",
		"/usr/local/lib64/librte_eal.so",
};

static int
dpdk_init(void)
{
	static const char *argv[] = { "unused",
					"--no-pci",
					"--log-level=lib.eal:debug",
					"--file-prefix=pid_0xffffffff" };
	char *eal_path;
	void *handle;
	int (*di)(int argc, const char **argv);
	char *fp;
	char *error;
	int rc;
	int i;

	eal_path = getenv("DSA_PERF_MICROS_EAL_PATH");
	if (eal_path)
		handle = dlopen(eal_path, RTLD_LAZY);
	else {
		for (handle = NULL, i = 0; !handle && i < ARRAY_SIZE(eal_loc); i++)
			handle = dlopen(eal_loc[i], RTLD_LAZY);
	}

	if (!handle) {
		ERR("failed to open librte_eal.so, tried\n");
		if (eal_path)
			ERR("%s\n", eal_path);
		else {
			for (i = 0; i < ARRAY_SIZE(eal_loc); i++)
				ERR("%s\n", eal_loc[i]);
		}
		exit(1);
	}

	di = dlsym(handle, "rte_eal_init");
	if (!di) {
		ERR("Failed to get the function rte_eal_init\n");
		exit(1);
	}
	error = dlerror();
	if (error != NULL) {
		ERR("%s\n", error);
		exit(1);
	}

	rte_malloc_socket = dlsym(handle, "rte_malloc_socket");
	error = dlerror();
	if (error != NULL) {
		ERR("%s\n", error);
		exit(1);
	}

	fp = strdup(argv[ARRAY_SIZE(argv) - 1]);
	if (fp == NULL) {
		ERR("Failed to copy string\n");
		exit(1);
	}

	snprintf(fp, strlen(argv[ARRAY_SIZE(argv) - 1]) + 1,
		"--file-prefix=pid_0x%x", getpid());
	argv[ARRAY_SIZE(argv) - 1] = fp;

	rc = (*di)(ARRAY_SIZE(argv), argv);
	free(fp);

	return rc < 0 ? rc : 0;
}

int
user_driver_init(struct tcfg *tcfg)
{
	FILE *fp;
	int i, rc;

	uio_cnt = uio_dev_count();
	vfio_cnt = vfio_dev_count();

	if (uio_cnt)
		tcfg->malloc = phys_malloc;

	if (uio_cnt && vfio_cnt) {
		ERR("Unexpected non-zero uio(%d) and vfio(%d) counts, either has to be zero\n",
			uio_cnt, vfio_cnt);
		return -1;
	}

	nb_udev = uio_cnt + vfio_cnt;
	if (nb_udev == 0) {
		ERR("zero uio/vfio driver devices detected\n");
		return -1;
	}

	if (uio_cnt) {
		rc = dpdk_init();
		if (rc) {
			ERR("dpdk_init failed\n");
			return rc;
		}
	}

	udi = calloc(nb_udev, sizeof(udi[0]));
	if (!udi) {
		ERR("dpdk_init failed\n");
		return -ENOMEM;
	}

	if (uio_cnt)
		fp = popen(BDF_CMD(uio_pci_generic), "r");
	else
		fp = popen(BDF_CMD(vfio-pci), "r");

	if (!fp) {
		free(udi);
		ERR("dpdk_init failed\n");
		return -EIO;
	}

	nb_wq = 0;
	rc = 0;

	for (i = 0; i < nb_udev; i++) {
		char line[80];
		char *cmd;

		if (fgets(line, sizeof(line), fp) == 0)
			break;

		rc = sscanf(line, "%m[^\n]", &udi[i].bdf);
		if (rc == 0)
			break;

		udi[i].numa_node = -1;
		rc = asprintf(&cmd, "cat /sys/bus/pci/devices/%s/numa_node", udi[i].bdf);
		if (!(rc == 0 || rc == -1)) {
			FILE *fp_numa;

			fp_numa = popen(cmd, "r");
			if (fp_numa) {
				if (fscanf(fp_numa, "%d", &udi[i].numa_node) != 1)
					ERR("Unable to parse numa node\n");
			} else
				ERR("Unable to parse numa node, popen %s failed\n", cmd);
			if (fp_numa)
				pclose(fp_numa);
		} else
			ERR("parse numa node cmd construction failed\n");

		free(cmd);
		udi[i].dev_id = pci_dev_id(udi[i].bdf);
		if (udi[i].dev_id < 0) {
			rc = udi[i].dev_id;
			if (rc)
				break;
		}
		udi[i].nb_engines = tcfg->nb_user_eng;
		udi[i].nb_wq = 1;
		udi[i].wq_avail = 0x1;
		nb_wq += udi[i].nb_wq;
		rc = 0;
	}

	pclose(fp);

	if (rc)
		return rc;

	uwi = calloc(nb_wq, sizeof(*uwi));

	return uwi ? 0 : -ENOMEM;
}

static int
find_free_wq_info(const void *key, const void *p2)
{
	const struct ud_wq_info *uwi = p2;

	return uwi->ptr == key ? 0 : 1;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int
common_init(int uio_cnt, struct udev_info *pd)
{
	uint32_t tph, tmp;
	int rc;

	rc = read_tph(pd->bdf, &tph);
	if (rc == -1) {
		ERR("Error reading tph\n");
		return -EIO;
	}

	if (!tph) {
		ERR("TPH capability is disabled\n");
		return -EINVAL;
	}

	rc = uio_cnt ? uio_init(pd) : vfio_init(pd);
	if (rc)
		return rc;

	rc = read_tph(pd->bdf, &tmp);
	if (rc == -1) {
		ERR("Error reading tph\n");
		return -EIO;
	}

	if (tmp == tph)
		return 0;

	rc = write_tph(pd->bdf, tph);
	if (rc == -1) {
		ERR("Failed to write tph value\n");
		return -EIO;
	}

	return 0;
}

static struct ud_wq_info *
ud_wq_find(char *dname, int wq_id, int shared, int numa_node)
{
	struct udev_info *pd;
	struct ud_wq_info *pq;
	size_t s;
	int i;

	if (shared)
		return NULL;

	pthread_mutex_lock(&lock);

	s = nb_wq;
	pq = lfind(NULL, uwi, &s, sizeof(*uwi), find_free_wq_info);
	if (pq == NULL)
		return NULL;

	for (i = 0; i < nb_udev; i++) {
		int rc;

		pd = &udi[i];

		if (dname) {
			if (strcmp(dname, pd->bdf + strlen("0000:")))
				continue;
		}

		if ((!dname && pd->numa_node != -1) && (numa_node != pd->numa_node))
			continue;

		if (dname && pd->wq_avail == 0)
			break;

		if (pd->wq_avail == 0)
			continue;

		if (wq_id != -1)
			if (!(pd->wq_avail & (1 << wq_id)))
				break;

		if (wq_id == -1)
			wq_id = __builtin_ffs(pd->wq_avail) - 1;

		if (!pd->init_done) {
			rc = common_init(uio_cnt, pd);
			if (rc) {
				if (dname)
					break;
				else
					continue;
			}
			pd->init_done = true;
		}

		idxd_pci_dev_command(pd->pci, idxd_enable_wq);

		pd->wq_avail &= ~(1 << wq_id);
		pq->ptr = (void *)(pd->resource[1] + wq_id * 4096 * 4);
		pq->wq_id = wq_id;
		pq->udi = pd;
		break;
	}

	pthread_mutex_unlock(&lock);

	return pq->ptr ? pq : NULL;
}

void *
ud_wq_get(char *dname, int wq_id, int shared, int numa_node)
{
	struct ud_wq_info *uwi;

	uwi = ud_wq_find(dname, wq_id, shared, numa_node);

	return uwi ? uwi->ptr : NULL;
}

static int
match_wq(const void *key, const void *p2)
{
	const struct ud_wq_info *uwi =  p2;

	return uwi->ptr == key ? 0 : 1;
}

void ud_wq_info_get(void *ptr, struct wq_info *wq_info)
{
	struct udev_info *pd;
	struct ud_wq_info *pq;
	size_t s;

	s = nb_wq;
	pq = lfind(ptr, uwi, &s, sizeof(*uwi), match_wq);
	pd = pq->udi;

	wq_info->size = idxd_get_wq_cfg(pd->pci, 0)[WQ_SIZE_IDX];
	wq_info->dwq = 1;
	wq_info->dmap_fd = pd->dmap_fd;
	wq_info->dname = pd->bdf;
	wq_info->dev_type = pd->dev_id == 0xb25 ? DSA : IAX;
}

void ud_wq_unmap(void *ptr)
{
	struct udev_info *pd;
	struct ud_wq_info *pq;
	size_t s;

	s = nb_wq;
	pq = lfind(ptr, uwi, &s, sizeof(*uwi), match_wq);
	pd = pq->udi;
	pd->wq_avail |= (pq->wq_id << 1);
	idxd_pci_dev_command(pd->pci, idxd_disable_wq);
	pq->ptr = NULL;
}

#define RTE_BAD_IOVA (~0UL)
#define PFN_MASK_SIZE	8

static uint64_t
rte_mem_virt2phy(const void *virtaddr)
{
	int fd, rc;
	uint64_t page, physaddr;
	unsigned long virt_pfn;
	int page_size;
	off_t offset;

	/* standard page size */
	page_size = getpagesize();

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		ERR("%s(): cannot open /proc/self/pagemap: %s\n",
			__func__, strerror(errno));
		return RTE_BAD_IOVA;
	}

	virt_pfn = (unsigned long)virtaddr / page_size;
	offset = sizeof(uint64_t) * virt_pfn;
	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		ERR("%s(): seek error in /proc/self/pagemap: %s\n",
				__func__, strerror(errno));
		close(fd);
		return RTE_BAD_IOVA;
	}

	rc = read(fd, &page, PFN_MASK_SIZE);
	close(fd);
	if (rc < 0) {
		ERR("cannot read /proc/self/pagemap: %s\n", strerror(errno));
		return RTE_BAD_IOVA;
	} else if (rc != PFN_MASK_SIZE) {
		ERR("read %d bytes from /proc/self/pagemap but expected %d:\n",
			rc, PFN_MASK_SIZE);
		return RTE_BAD_IOVA;
	}

	/*
	 * the pfn (page frame number) are bits 0-54 (see
	 * pagemap.txt in linux Documentation)
	 */
	if ((page & 0x7fffffffffffffULL) == 0)
		return RTE_BAD_IOVA;

	physaddr = ((page & 0x7fffffffffffffULL) * page_size)
		+ ((unsigned long)virtaddr % page_size);

	return physaddr;
}

uint64_t user_virt2iova(void *p)
{
	return vfio_cnt ? (uint64_t)p : rte_mem_virt2phy(p);
}

int
ud_iommu_disabled(void)
{
	return !!uio_cnt;
}
