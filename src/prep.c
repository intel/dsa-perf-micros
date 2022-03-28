// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <linux/idxd.h>
#include <linux/types.h>
#include "common.h"
#include "dsa.h"
#include "device.h"
#include "prep.h"

/*
 * T10 Protection Information tuple.
 */
struct t10_pi_tuple {
	__be16 guard_tag;	/* Checksum */
	__be16 app_tag;		/* Opaque storage */
	__be32 ref_tag;		/* Target LBA or indirect LBA */
};

static const uint16_t bl_tbl[] = { 512, 520, 4096, 4104 };

static inline
uint16_t dif_block_len(uint8_t idx)
{
	return bl_tbl[idx];
}

static void
init_memmove_desc_addr(struct tcfg_cpu *tcpu, int begin, int count)
{
	uint64_t off = tcpu->tcfg->bstride * begin;
	struct dsa_hw_desc *d = &tcpu->desc[begin];
	int i;

	for (i = 0; i < count; i++, d++) {
		d->src_addr = rte_mem_virt2iova(tcpu->src + off);
		d->dst_addr = rte_mem_virt2iova(tcpu->dst + off);
		off = off + tcpu->tcfg->bstride;
	}
}

static void
init_ap_delta_addr(struct tcfg_cpu *tcpu, int begin, int count)
{
	struct tcfg *tcfg = tcpu->tcfg;
	struct dsa_hw_desc *d = &tcpu->desc[begin];
	char *src = (char *)tcpu->delta;
	char *dst = tcpu->dst;
	uint64_t src_stride = tcfg->delta_rec_size;
	uint64_t dst_stride = tcfg->bstride;
	uint64_t src_off = src_stride * begin;
	uint64_t dst_off = dst_stride * begin;
	int i;

	for (i = 0; i < count; i++, d++) {
		d->src_addr = rte_mem_virt2iova(src + src_off + i * src_stride);
		d->dst_addr = rte_mem_virt2iova(dst + dst_off + i * dst_stride);
	}
}

static void
init_dst_addr(struct tcfg_cpu *tcpu, int begin, int count)
{
	uint64_t off = tcpu->tcfg->bstride * begin;
	struct dsa_hw_desc *d = &tcpu->desc[begin];
	int i;

	for (i = 0; i < count; i++, d++)
		d->dst_addr = rte_mem_virt2iova(tcpu->dst + off + i * tcpu->tcfg->bstride);
}

static void
init_src_addr(struct tcfg_cpu *tcpu, int begin, int count)
{
	uint64_t off = tcpu->tcfg->bstride * begin;
	struct dsa_hw_desc *d = &tcpu->desc[begin];
	int i;

	for (i = 0; i < count; i++, d++)
		d->src_addr = rte_mem_virt2iova(tcpu->src + off + i * tcpu->tcfg->bstride);
}

static void
init_src_addrs(struct tcfg_cpu *tcpu, int begin, int count)
{
	struct dsa_hw_desc *d = &tcpu->desc[begin];
	uint32_t off = tcpu->tcfg->bstride * begin;
	int i;

	for (i = 0; i < count; i++, d++) {
		d->src_addr = rte_mem_virt2iova(tcpu->src1 + off);
		d->src2_addr = rte_mem_virt2iova(tcpu->src2 + off);
		off = off + tcpu->tcfg->bstride;
	}
}

static void
init_dc_addr(struct tcfg_cpu *tcpu, int begin, int count)
{
	struct dsa_hw_desc *d = &tcpu->desc[begin];
	struct tcfg *tcfg = tcpu->tcfg;
	uint32_t off = tcfg->bstride * begin;
	int i;

	for (i = 0; i < count; i++, d++) {
		d->src_addr = rte_mem_virt2iova(tcpu->src + off);
		d->dst_addr = rte_mem_virt2iova(tcpu->dst1 + off);
		d->dest2 = rte_mem_virt2iova(tcpu->dst2 + off);
		off = off + tcpu->tcfg->bstride;
	}
}

static void
init_dif_addr(struct tcfg_cpu *tcpu, int begin, int count)
{
	struct dsa_hw_desc *d = &tcpu->desc[begin];
	struct tcfg *tcfg = tcpu->tcfg;
	uint32_t off_src, off_dst;
	uint32_t i;

	off_src = begin * tcfg->bstride_arr[0];
	off_dst = begin * tcfg->bstride_arr[1];

	for (i = 0; i < count; i++, d++) {
		d->src_addr = rte_mem_virt2iova(tcpu->src + off_src);
		off_src += tcfg->bstride_arr[0];
		if (!tcpu->dst)
			continue;
		d->dst_addr = rte_mem_virt2iova(tcpu->dst + off_dst);
		off_dst += tcfg->bstride_arr[1];
	}
}

void
init_desc_addr(struct tcfg_cpu *tcpu, int begin, int count)
{
	switch (tcpu->tcfg->op) {

	case DSA_OPCODE_MEMMOVE:
	case DSA_OPCODE_COPY_CRC:
		init_memmove_desc_addr(tcpu, begin, count);
		break;

	case DSA_OPCODE_MEMFILL:
		init_dst_addr(tcpu, begin, count);
		break;

	case DSA_OPCODE_CRCGEN:
	case DSA_OPCODE_COMPVAL:
		init_src_addr(tcpu, begin, count);
		break;

	case DSA_OPCODE_COMPARE:
	case DSA_OPCODE_CR_DELTA:
		init_src_addrs(tcpu, begin, count);
		break;

	case DSA_OPCODE_AP_DELTA:
		init_ap_delta_addr(tcpu, begin, count);
		break;

	case DSA_OPCODE_DUALCAST:
		init_dc_addr(tcpu, begin, count);
		break;

	case DSA_OPCODE_DIF_CHECK:
	case DSA_OPCODE_DIF_STRP:
	case DSA_OPCODE_DIF_INS:
	case DSA_OPCODE_DIF_UPDT:
		init_dif_addr(tcpu, begin, count);
		break;

	}
}

static uint16_t
dsa_calculate_crc_t10dif(unsigned char *buffer, size_t len, uint8_t flags)
{
	uint16_t crc;
	unsigned int i = 0;


	/* Set the seed to be either 0 or all F's. */
	crc = (flags & DIF_INVERT_CRC_SEED) ? 0xFFFF : 0;

	for (i = 0; i < len; i++)
		crc = (crc << 8) ^ t10_dif_crc_table[((crc >> 8) ^ buffer[i]) & 0xff];

	return (flags & DIF_INVERT_CRC_RESULT) ? ~crc : crc;
}

static void
prep_dsa_memmove(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct tcfg *tcfg = tcpu->tcfg;
	struct dsa_hw_desc *descs = tcpu->desc;
	uint32_t i;

	init_buffers(tcpu);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		init_memmove_desc_addr(tcpu, i, 1);
	}
}

static void
prep_dsa_dst_only(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct tcfg *tcfg = tcpu->tcfg;
	struct dsa_hw_desc *descs = tcpu->desc;
	uint32_t i;

	/* not initializing buffer */

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		init_dst_addr(tcpu, i, 1);
	}
}

static void
prep_dsa_memfill(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct tcfg *tcfg = tcpu->tcfg;

	memset(&tcfg->fill, TEST_CHAR, sizeof(tcfg->pat));
	desc->pattern = tcfg->fill;
	prep_dsa_dst_only(tcpu, desc);
}

static void
prep_dsa_src_only(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct dsa_hw_desc *descs = tcpu->desc;
	struct tcfg *tcfg = tcpu->tcfg;
	uint32_t i;

	init_buffers(tcpu);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		init_src_addr(tcpu, i, 1);
	}
}

static void
prep_dsa_cmpval(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct tcfg *tcfg = tcpu->tcfg;

	memset(&tcfg->pat, TEST_CHAR, sizeof(tcfg->pat));
	desc->comp_pattern = tcfg->pat;
	prep_dsa_src_only(tcpu, desc);
}

static void
prep_dsa_memcmp(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct tcfg *tcfg = tcpu->tcfg;
	struct dsa_hw_desc *descs = tcpu->desc;
	uint32_t i;
	init_buffers(tcpu);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		init_src_addrs(tcpu, i, 1);
	}
}

static void
prep_dsa_cr_delta(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct dsa_hw_desc *descs = tcpu->desc;
	struct tcfg *tcfg = tcpu->tcfg;
	uint32_t delta_rec_size = tcfg->delta_rec_size;
	struct delta_rec *dptr;
	uint32_t i;

	init_buffers(tcpu);

	dptr = tcpu->delta;
	desc->max_delta_size = min(80, tcfg->delta_rec_size);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		init_src_addrs(tcpu, i, 1);
		descs[i].delta_addr = rte_mem_virt2iova(dptr);
		dptr +=  delta_rec_size/sizeof(struct delta_rec);
	}
}

static void
prep_dsa_ap_delta(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	uint32_t i;
	struct dsa_hw_desc *descs = tcpu->desc;
	struct tcfg *tcfg = tcpu->tcfg;

	init_buffers(tcpu);

	desc->delta_rec_size = tcfg->delta_rec_size;

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		init_ap_delta_addr(tcpu, i, 1);
	}
}

static void
prep_dsa_dc(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	uint32_t i;
	struct dsa_hw_desc *descs = tcpu->desc;
	struct tcfg *tcfg = tcpu->tcfg;

	init_buffers(tcpu);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		init_dc_addr(tcpu, i, 1);
	}
}

static inline uint32_t
dif_xfer_size(struct tcfg *tcfg)
{
	return	tcfg->blen + 8 * tcfg->blen/dif_block_len(tcfg->bl_idx);
}

static void
prepare_dif_buf(struct tcfg *tcfg, char *b, int n, int dif_flags,
		uint32_t ref_tag, uint16_t app_tag)
{
	int i, j;
	struct t10_pi_tuple *t10;
	int nb_block;

	nb_block = tcfg->blen/tcfg->bl_len;

	for (i = 0; i < n; i++) {
		char *block = b;

		for (j = 0; j < nb_block; j++) {

			t10 = (struct t10_pi_tuple *)&block[tcfg->bl_len];

			t10->guard_tag = dsa_calculate_crc_t10dif((unsigned char *)block,
							tcfg->bl_len,
							(uint8_t)dif_flags);
			t10->guard_tag = htobe16(t10->guard_tag);
			t10->app_tag = htobe16(app_tag);
			t10->ref_tag = htobe32(ref_tag);

			block += tcfg->bl_len + 8;
		}

		b += tcfg->bstride;
	}
}

static void
dsa_prep_dif_flags(int op, int blk_idx, struct dsa_hw_desc *hw,
		uint16_t app_tag, uint32_t ref_tag)
{
	switch (op) {

	case DSA_OPCODE_DIF_STRP:
	case DSA_OPCODE_DIF_CHECK:
		hw->chk_app_tag_seed = app_tag;
		hw->chk_ref_tag_seed = ref_tag;
		hw->chk_app_tag_mask = 0xffff;
		hw->src_dif_flags = (1 << 7) | (1 << 6) | (1 << 5);
		hw->dif_chk_flags = blk_idx;
		hw->dif_chk_res2[0] = 0;
		hw->dif_chk_res2[1] = 0;
		break;

	case DSA_OPCODE_DIF_INS:
		hw->ins_app_tag_seed = app_tag;
		hw->ins_ref_tag_seed = ref_tag;
		hw->ins_app_tag_mask = 0xffff;
		/* 1 << 7 => fixed ref tag, 0 << 4 => fixed app tag */
		hw->dest_dif_flag = 1 << 7;
		hw->dif_ins_flags = blk_idx;
		hw->dif_ins_res2[0] = 0;
		hw->dif_ins_res2[1] = 0;
		break;

	case DSA_OPCODE_DIF_UPDT:
		/*
		 * src ref tag type is fixed
		 */
		hw->src_upd_flags = 1 << 7;

		/*
		 * dest ref tag(7) = fixed,
		 * ref tag passthru(6) = 1, guard field(5) = 1
		 * app tag passthru(3) = 1
		 * respective fields are copied from src to dest
		 */
		hw->upd_dest_flags = (1 << 7) | (1 << 6) | (1 << 5) | (1 << 3);
		hw->dif_upd_flags = blk_idx;
		hw->dif_upd_res[0] = 0;
		hw->dif_upd_res[1] = 0;
		hw->dif_upd_res[2] = 0;
		hw->dif_upd_res[3] = 0;
		hw->dif_upd_res[4] = 0;
		hw->src_ref_tag_seed = ref_tag;
		hw->src_app_tag_mask = 0xffff;
		hw->src_app_tag_seed = app_tag;
		hw->src_app_tag_mask = 0xffff;
		hw->dest_ref_tag_seed = 0;
		hw->dest_app_tag_mask = 0;
		hw->dest_app_tag_seed = 0;
		break;
	}
}

static void
prep_dsa_dif(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct dsa_hw_desc *descs = tcpu->desc;
	struct tcfg *tcfg = tcpu->tcfg;
	char *src;
	uint32_t i;
	const uint32_t ref_tag = 0x87654321;
	const uint16_t app_tag = 0xdcba;
	int dif_flags = 0;
	uint32_t off_src;

	off_src = tcfg->bstride_arr[0];
	src = tcpu->src;
	dsa_prep_dif_flags(tcfg->op, tcfg->bl_idx, desc, app_tag, ref_tag);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		if (tcfg->op != DSA_OPCODE_DIF_INS)
			prepare_dif_buf(tcfg, src, 1, dif_flags, ref_tag, app_tag);
		descs[i].xfer_size =
			tcfg->op == DSA_OPCODE_DIF_INS ? tcfg->blen :
							dif_xfer_size(tcfg);
		init_dif_addr(tcpu, i, 1);
		src += off_src;
	}
}

static void
prep_dsa_crc_gen(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	prep_dsa_src_only(tcpu, desc);
}

static void
prep_dsa_copy_crc(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	prep_dsa_memmove(tcpu, desc);
}

static void
prep_dsa_cflush(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	prep_dsa_dst_only(tcpu, desc);
}

static void
prep_dsa_noop(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	struct dsa_hw_desc *descs = tcpu->desc;
	struct tcfg *tcfg = tcpu->tcfg;
	uint32_t i;

	for (i = 0; i < tcfg->nb_bufs; i++)
		descs[i] = *desc;
}

static void
test_prep_batch_desc(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg;
	struct dsa_hw_desc *desc;
	int i;

	tcfg = tcpu->tcfg;
	if (tcfg->batch_sz <= 1)
		return;

	for (i = 0; i < tcfg->nb_desc; i++) {
		desc = &tcpu->bdesc[i];
		memset(desc, 0, sizeof(*desc));
		desc->opcode = DSA_OPCODE_BATCH;
		desc->desc_count = min(tcfg->batch_sz,
					tcfg->nb_bufs - i * tcfg->batch_sz);
		desc->desc_list_addr = rte_mem_virt2iova(&tcpu->desc[i * tcfg->batch_sz]);
		desc->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		desc->completion_addr = rte_mem_virt2iova(&tcpu->bcomp[i]);
	}
}

#define WR_FLAGS (IDXD_OP_FLAG_CC | IDXD_OP_FLAG_STORD)

void
test_prep_desc(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	unsigned int i;
	struct dsa_hw_desc desc = {}, *pd;
	uint32_t resv_flags[DSA_OPCODE_CFLUSH] = {
			[DSA_OPCODE_NOOP] = WR_FLAGS,
			[DSA_OPCODE_COMPARE] = WR_FLAGS,
			[DSA_OPCODE_COMPVAL] = WR_FLAGS,
			[DSA_OPCODE_CRCGEN] = WR_FLAGS,
			[DSA_OPCODE_DIF_CHECK] = WR_FLAGS };


	desc.opcode = tcfg->op;
	desc.flags = IDXD_OP_FLAG_CRAV;
	desc.flags |= IDXD_OP_FLAG_RCR;

	if (tcfg->op != DSA_OPCODE_NOOP)
		desc.xfer_size = tcfg->blen;

	tcfg = tcpu->tcfg;

	switch (tcfg->op) {

	case DSA_OPCODE_MEMMOVE:
		prep_dsa_memmove(tcpu, &desc);
		break;

	case DSA_OPCODE_MEMFILL:
		prep_dsa_memfill(tcpu, &desc);
		break;

	case DSA_OPCODE_COMPARE:
		prep_dsa_memcmp(tcpu, &desc);
		break;

	case DSA_OPCODE_COMPVAL:
		prep_dsa_cmpval(tcpu, &desc);
		break;

	case DSA_OPCODE_CR_DELTA:
		prep_dsa_cr_delta(tcpu, &desc);
		break;

	case DSA_OPCODE_AP_DELTA:
		prep_dsa_ap_delta(tcpu, &desc);
		break;

	case DSA_OPCODE_DUALCAST:
		prep_dsa_dc(tcpu, &desc);
		break;

	case DSA_OPCODE_DIF_CHECK:
	case DSA_OPCODE_DIF_STRP:
	case DSA_OPCODE_DIF_INS:
	case DSA_OPCODE_DIF_UPDT:
		prep_dsa_dif(tcpu, &desc);
		break;

	case DSA_OPCODE_CRCGEN:
		prep_dsa_crc_gen(tcpu, &desc);
		break;

	case DSA_OPCODE_COPY_CRC:
		prep_dsa_copy_crc(tcpu, &desc);
		break;

	case DSA_OPCODE_CFLUSH:
		prep_dsa_cflush(tcpu, &desc);
		break;

	case DSA_OPCODE_NOOP:
		prep_dsa_noop(tcpu, &desc);
		break;

	default:
		ERR("Unrecognized op %d\n", tcfg->op);
		tcpu->err = -EINVAL;
		return;
	}

	pd = tcpu->desc;
	for (i = 0; i < tcfg->nb_bufs; i++) {
		char *c;

		c = (char *)tcpu->comp + i * comp_rec_size(tcpu);
		pd[i].completion_addr = rte_mem_virt2iova(c);
		pd[i].flags |= tcfg->ccmask;
		if (tcfg->flags_nth_desc > 0 && (i+1) % tcfg->flags_nth_desc == 0) {
			pd[i].flags &= tcfg->flags_cmask;
			pd[i].flags |= tcfg->flags_smask;
		}
		pd[i].flags &= ~resv_flags[tcfg->op];
	}

	test_prep_batch_desc(tcpu);

	if (tcfg->drain_desc) {
		uint64_t	cp_addr;

		/*
		 * for -Y option, we need to convert the last desc to drain.
		 */
		pd = desc_ptr(tcpu) + tcfg->nb_desc - 1;
		cp_addr = pd->completion_addr;
		memset(pd, 0, sizeof(struct dsa_hw_desc));
		pd->flags = IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCR;
		pd->opcode = DSA_OPCODE_DRAIN;
		pd->completion_addr = cp_addr;
	}
}
