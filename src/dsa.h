// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#ifndef __DSA_H__
#define __DSA_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/idxd.h>


#include "crc16_t10_lookup.h"

#define MAX_PATH_LENGTH 1024
#define DSA_BATCH_OPCODES 0x278
#define DIF_INVERT_CRC_SEED         (1 << 2)
#define DIF_INVERT_CRC_RESULT       (1 << 3)

// DIF index's.
#define DIF_BLK_GRD_1  0
#define DIF_BLK_GRD_2  1
#define DIF_APP_TAG_1  2
#define DIF_APP_TAG_2  3
#define DIF_REF_TAG_1  4
#define DIF_REF_TAG_2  5
#define DIF_REF_TAG_3  6
#define DIF_REF_TAG_4  7

/* Dump DSA hardware descriptor to log */
static inline void dump_desc(struct dsa_hw_desc *hw)
{
	struct dsa_raw_desc *rhw = (void *)hw;
	int i;

	printf("desc addr: %p\n", hw);

	for (i = 0; i < 8; i++)
		printf("desc[%d]: 0x%016lx\n", i, rhw->field[i]);
}

static inline unsigned char enqcmd(struct dsa_hw_desc *desc,
			volatile void *reg)
{
	unsigned char retry;

	asm volatile(".byte 0xf2, 0x0f, 0x38, 0xf8, 0x02\t\n"
			"setz %0\t\n"
			: "=r"(retry) : "a" (reg), "d" (desc));
	return retry;
}

static inline void movdir64b(struct dsa_hw_desc *desc, volatile void *reg)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02\t\n"
		: : "a" (reg), "d" (desc));
}

static __always_inline
void dsa_desc_submit(void *wq_portal, int dedicated,
		struct dsa_hw_desc *hw)
{
	if (dedicated)
		movdir64b(hw, wq_portal);
	else /* retry infinitely, a retry param is not needed at this time */
		while (enqcmd(hw, wq_portal))
			;
}

#endif
