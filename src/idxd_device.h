// SPDX-License-Identifier: GPL-2.0
#ifndef __IDXD_DEVICE_H__
#define __IDXD_DEVICE_H__

struct wq_info;

void *idxd_wq_get(char *dname, int wq_id, int shared, int numa_node);
void idxd_wq_info_get(void *ptr, struct wq_info *wq_info);
int idxd_wq_size(void *ptr);
int idxd_wq_dedicated(void *ptr);
void idxd_wq_unmap(void *wq);

#endif
