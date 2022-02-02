// SPDX-License-Identifier: GPL-2.0
#ifndef __CPU_H__
#define __CPU_H__

struct tcfg_cpu;
struct delta_rec;

void test_memcpy(struct tcfg_cpu *tcpu);
void cr_delta(char *src1, char *src2, struct delta_rec *delta, uint64_t len);

#endif
