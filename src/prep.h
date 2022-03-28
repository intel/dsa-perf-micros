// SPDX-License-Identifier: GPL-2.0
#ifndef __PREP_H__
#define __PREP_H__

struct tcfg_cpu;

void test_prep_desc(struct tcfg_cpu *tcpu);
void init_desc_addr(struct tcfg_cpu *tcpu, int begin, int count);

#endif
