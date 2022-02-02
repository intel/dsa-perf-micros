// SPDX-License-Identifier: GPL-2.0
#ifndef __DEVICE_H__
#define __DEVICE_H__

struct tcfg;
struct wq_info;

int driver_init(struct tcfg *tcfg);
void *wq_map(char *dname, int wq, int shared, int numa_node);
void wq_unmap(void *ptr);
void wq_info_get(void *wq, struct wq_info *wq_info);
int dmap(int fd, void *va, ssize_t len);
int dunmap(int fd, void *va, ssize_t len);
uint64_t rte_mem_virt2iova(void *p);
int iommu_disabled(void);

#endif
