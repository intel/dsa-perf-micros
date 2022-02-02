// SPDX-License-Identifier: GPL-2.0
#ifndef __INIT_H__
#define __INIT_H__

struct tcfg;
struct tcfg_cpu;
int test_init_global(struct tcfg *tcfg);
void test_init_percpu(struct tcfg_cpu *tcpu);
void free_proc_mem(struct tcfg_cpu *tcpu);
void test_free(struct tcfg *tcfg);
void dunmap_per_cpu(struct tcfg_cpu *tcpu);
#endif
