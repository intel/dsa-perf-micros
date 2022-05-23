// SPDX-License-Identifier: GPL-2.0
#ifndef __UTIL_H__
#define __UTIL_H__

struct tcfg_cpu;
struct tcfg;

void print_tcfg(struct tcfg *tcfg);
int iotlb_invd(struct tcfg *tcfg);
void do_cache_ops(struct tcfg_cpu *tcpu);
int verify_buf(struct tcfg_cpu *tcpu);
void do_results(struct tcfg *tcfg);
int cpu_pin(uint32_t cpu);
int test_barrier_init(struct tcfg *tcfg);
int test_barrier(struct tcfg *tcfg, bool err);
void test_barrier_free(struct tcfg *tcfg);
void calc_cpu_for_sec(struct tcfg *tcfg, int sec);

#endif
