// SPDX-License-Identifier: GPL-2.0
#ifndef __USER_DEVICE_H__
#define __USER_DEVICE_H__

#include <stdint.h>

struct wq_info;
struct tcfg;

uint64_t user_virt2iova(void *p);
int user_driver_init(struct tcfg *tcfg);
void *ud_wq_get(char *dname, int wq_id, int shared, int numa_node);
void ud_wq_info_get(void *wq, struct wq_info *wq_info);
void ud_wq_unmap(void *wq);
int ud_dmap(int fd, void *va, ssize_t len);
int ud_dunmap(int container, void *va, ssize_t len);
int ud_iommu_disabled(void);

#endif
