// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <linux/idxd.h>
#include "common.h"
#include "dsa.h"
#include "device.h"
#include "prep.h"

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

/**
 * Credit Martin K. Petersen (Oracle)
 * Table generated using the following polynomium:
 * x^16 + x^15 + x^11 + x^9 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
 * gt: 0x8bb7
 */
static const uint16_t t10_dif_crc_table[256] = {
	0x0000, 0x8BB7, 0x9CD9, 0x176E, 0xB205, 0x39B2, 0x2EDC, 0xA56B,
	0xEFBD, 0x640A, 0x7364, 0xF8D3, 0x5DB8, 0xD60F, 0xC161, 0x4AD6,
	0x54CD, 0xDF7A, 0xC814, 0x43A3, 0xE6C8, 0x6D7F, 0x7A11, 0xF1A6,
	0xBB70, 0x30C7, 0x27A9, 0xAC1E, 0x0975, 0x82C2, 0x95AC, 0x1E1B,
	0xA99A, 0x222D, 0x3543, 0xBEF4, 0x1B9F, 0x9028, 0x8746, 0x0CF1,
	0x4627, 0xCD90, 0xDAFE, 0x5149, 0xF422, 0x7F95, 0x68FB, 0xE34C,
	0xFD57, 0x76E0, 0x618E, 0xEA39, 0x4F52, 0xC4E5, 0xD38B, 0x583C,
	0x12EA, 0x995D, 0x8E33, 0x0584, 0xA0EF, 0x2B58, 0x3C36, 0xB781,
	0xD883, 0x5334, 0x445A, 0xCFED, 0x6A86, 0xE131, 0xF65F, 0x7DE8,
	0x373E, 0xBC89, 0xABE7, 0x2050, 0x853B, 0x0E8C, 0x19E2, 0x9255,
	0x8C4E, 0x07F9, 0x1097, 0x9B20, 0x3E4B, 0xB5FC, 0xA292, 0x2925,
	0x63F3, 0xE844, 0xFF2A, 0x749D, 0xD1F6, 0x5A41, 0x4D2F, 0xC698,
	0x7119, 0xFAAE, 0xEDC0, 0x6677, 0xC31C, 0x48AB, 0x5FC5, 0xD472,
	0x9EA4, 0x1513, 0x027D, 0x89CA, 0x2CA1, 0xA716, 0xB078, 0x3BCF,
	0x25D4, 0xAE63, 0xB90D, 0x32BA, 0x97D1, 0x1C66, 0x0B08, 0x80BF,
	0xCA69, 0x41DE, 0x56B0, 0xDD07, 0x786C, 0xF3DB, 0xE4B5, 0x6F02,
	0x3AB1, 0xB106, 0xA668, 0x2DDF, 0x88B4, 0x0303, 0x146D, 0x9FDA,
	0xD50C, 0x5EBB, 0x49D5, 0xC262, 0x6709, 0xECBE, 0xFBD0, 0x7067,
	0x6E7C, 0xE5CB, 0xF2A5, 0x7912, 0xDC79, 0x57CE, 0x40A0, 0xCB17,
	0x81C1, 0x0A76, 0x1D18, 0x96AF, 0x33C4, 0xB873, 0xAF1D, 0x24AA,
	0x932B, 0x189C, 0x0FF2, 0x8445, 0x212E, 0xAA99, 0xBDF7, 0x3640,
	0x7C96, 0xF721, 0xE04F, 0x6BF8, 0xCE93, 0x4524, 0x524A, 0xD9FD,
	0xC7E6, 0x4C51, 0x5B3F, 0xD088, 0x75E3, 0xFE54, 0xE93A, 0x628D,
	0x285B, 0xA3EC, 0xB482, 0x3F35, 0x9A5E, 0x11E9, 0x0687, 0x8D30,
	0xE232, 0x6985, 0x7EEB, 0xF55C, 0x5037, 0xDB80, 0xCCEE, 0x4759,
	0x0D8F, 0x8638, 0x9156, 0x1AE1, 0xBF8A, 0x343D, 0x2353, 0xA8E4,
	0xB6FF, 0x3D48, 0x2A26, 0xA191, 0x04FA, 0x8F4D, 0x9823, 0x1394,
	0x5942, 0xD2F5, 0xC59B, 0x4E2C, 0xEB47, 0x60F0, 0x779E, 0xFC29,
	0x4BA8, 0xC01F, 0xD771, 0x5CC6, 0xF9AD, 0x721A, 0x6574, 0xEEC3,
	0xA415, 0x2FA2, 0x38CC, 0xB37B, 0x1610, 0x9DA7, 0x8AC9, 0x017E,
	0x1F65, 0x94D2, 0x83BC, 0x080B, 0xAD60, 0x26D7, 0x31B9, 0xBA0E,
	0xF0D8, 0x7B6F, 0x6C01, 0xE7B6, 0x42DD, 0xC96A, 0xDE04, 0x55B3
};

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
	/*
	 * as per spec max_delta_size must not be less than the maximum number
	 * of deltas that can be generated from a single cache line (80 bytes)
	 */
	desc->max_delta_size = max(80, tcfg->delta_rec_size);

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
		uint8_t src_dif_flags, uint32_t ref_tag, uint16_t app_tag)
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
			ref_tag += !(src_dif_flags & 0x80);
			block += tcfg->bl_len + 8;
		}

		b += tcfg->bstride;
	}
}

static void
init_dif_expected(struct tcfg *tcfg, char *src, struct t10_pi_tuple *dif_data, int dif_flags,
		uint32_t ref_tag, uint16_t app_tag)
{
	int j;
	int nb_block;

	nb_block = tcfg->blen/tcfg->bl_len;

	for (j = 0; j < nb_block; j++) {
		dif_data->guard_tag = dsa_calculate_crc_t10dif((unsigned char *)src,
						tcfg->bl_len,
						(uint8_t)dif_flags);
		dif_data->guard_tag = htobe16(dif_data->guard_tag);
		dif_data->app_tag = htobe16(app_tag);
		dif_data->ref_tag = htobe32(ref_tag);

		src += tcfg->bl_len;
		if (tcfg->op == DSA_OPCODE_DIF_UPDT)
			src += sizeof(struct t10_pi_tuple);
		dif_data++;
	}
}

static void
dsa_prep_dif_flags(int op, int blk_idx, int dif_flags, struct dsa_hw_desc *hw,
		uint16_t app_tag, uint32_t ref_tag)
{
	switch (op) {

	case DSA_OPCODE_DIF_STRP:
	case DSA_OPCODE_DIF_CHECK:
		hw->chk_app_tag_seed = app_tag;
		hw->chk_ref_tag_seed = ref_tag;
		hw->chk_app_tag_mask = 0x0;
		/*
		 * b7: source DIF Reference Tag = incrementing
		 * b6: enable ref. tag field checking
		 * b5: Enable Guard field checking
		 * b4: Source Application Tag Type = fixed
		 * b3: Disable F Detect for Application Tag and Reference Tag fields
		 * b2: Disable F Detect for the Application Tag field
		 * b1: Disable All F Detect
		 * b0: Disable All F Detect Error
		 */
		hw->src_dif_flags = 0;
		hw->dif_chk_flags = dif_flags | blk_idx;
		hw->dif_chk_res2[0] = 0;
		hw->dif_chk_res2[1] = 0;
		break;

	case DSA_OPCODE_DIF_INS:
		hw->ins_app_tag_seed = app_tag;
		hw->ins_ref_tag_seed = ref_tag;
		hw->ins_app_tag_mask = 0xffff;
		hw->dest_dif_flag = 0;
		hw->dif_ins_flags = dif_flags | blk_idx;
		hw->dif_ins_res2[0] = 0;
		hw->dif_ins_res2[1] = 0;
		break;

	case DSA_OPCODE_DIF_UPDT:
		hw->src_upd_flags = 0;

		/*
		 * ref tag passthru(6) = 1, guard field(5) = 1
		 * app tag passthru(3) = 1
		 * respective fields are copied from src to dest
		 */
		hw->upd_dest_flags = (1 << 6) | (1 << 5) | (1 << 3);
		hw->dif_upd_flags = dif_flags | blk_idx;
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
	dsa_prep_dif_flags(tcfg->op, tcfg->bl_idx, dif_flags, desc, app_tag, ref_tag);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		descs[i] = *desc;
		if (tcfg->op != DSA_OPCODE_DIF_INS)
			prepare_dif_buf(tcfg, src, 1, desc->src_dif_flags, dif_flags, ref_tag, app_tag);
		descs[i].xfer_size =
			tcfg->op == DSA_OPCODE_DIF_INS ? tcfg->blen :
							dif_xfer_size(tcfg);

		if (tcfg->op == DSA_OPCODE_DIF_INS || tcfg->op == DSA_OPCODE_DIF_UPDT)
			init_dif_expected(tcfg, src, tcpu->dif_tag,
						dif_flags, ref_tag, app_tag);

		init_dif_addr(tcpu, i, 1);
		src += off_src;
	}
}

static void
prep_dsa_crc_gen(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	prep_dsa_src_only(tcpu, desc);
}

static const uint32_t crc32_table[256] = {
0x00000000, 0x1EDC6F41, 0x3DB8DE82, 0x2364B1C3, 0x7B71BD04, 0x65ADD245, 0x46C96386, 0x58150CC7,
0xF6E37A08, 0xE83F1549, 0xCB5BA48A, 0xD587CBCB, 0x8D92C70C, 0x934EA84D, 0xB02A198E, 0xAEF676CF,
0xF31A9B51, 0xEDC6F410, 0xCEA245D3, 0xD07E2A92, 0x886B2655, 0x96B74914, 0xB5D3F8D7, 0xAB0F9796,
0x05F9E159, 0x1B258E18, 0x38413FDB, 0x269D509A, 0x7E885C5D, 0x6054331C, 0x433082DF, 0x5DECED9E,
0xF8E959E3, 0xE63536A2, 0xC5518761, 0xDB8DE820, 0x8398E4E7, 0x9D448BA6, 0xBE203A65, 0xA0FC5524,
0x0E0A23EB, 0x10D64CAA, 0x33B2FD69, 0x2D6E9228, 0x757B9EEF, 0x6BA7F1AE, 0x48C3406D, 0x561F2F2C,
0x0BF3C2B2, 0x152FADF3, 0x364B1C30, 0x28977371, 0x70827FB6, 0x6E5E10F7, 0x4D3AA134, 0x53E6CE75,
0xFD10B8BA, 0xE3CCD7FB, 0xC0A86638, 0xDE740979, 0x866105BE, 0x98BD6AFF, 0xBBD9DB3C, 0xA505B47D,
0xEF0EDC87, 0xF1D2B3C6, 0xD2B60205, 0xCC6A6D44, 0x947F6183, 0x8AA30EC2, 0xA9C7BF01, 0xB71BD040,
0x19EDA68F, 0x0731C9CE, 0x2455780D, 0x3A89174C, 0x629C1B8B, 0x7C4074CA, 0x5F24C509, 0x41F8AA48,
0x1C1447D6, 0x02C82897, 0x21AC9954, 0x3F70F615, 0x6765FAD2, 0x79B99593, 0x5ADD2450, 0x44014B11,
0xEAF73DDE, 0xF42B529F, 0xD74FE35C, 0xC9938C1D, 0x918680DA, 0x8F5AEF9B, 0xAC3E5E58, 0xB2E23119,
0x17E78564, 0x093BEA25, 0x2A5F5BE6, 0x348334A7, 0x6C963860, 0x724A5721, 0x512EE6E2, 0x4FF289A3,
0xE104FF6C, 0xFFD8902D, 0xDCBC21EE, 0xC2604EAF, 0x9A754268, 0x84A92D29, 0xA7CD9CEA, 0xB911F3AB,
0xE4FD1E35, 0xFA217174, 0xD945C0B7, 0xC799AFF6, 0x9F8CA331, 0x8150CC70, 0xA2347DB3, 0xBCE812F2,
0x121E643D, 0x0CC20B7C, 0x2FA6BABF, 0x317AD5FE, 0x696FD939, 0x77B3B678, 0x54D707BB, 0x4A0B68FA,
0xC0C1D64F, 0xDE1DB90E, 0xFD7908CD, 0xE3A5678C, 0xBBB06B4B, 0xA56C040A, 0x8608B5C9, 0x98D4DA88,
0x3622AC47, 0x28FEC306, 0x0B9A72C5, 0x15461D84, 0x4D531143, 0x538F7E02, 0x70EBCFC1, 0x6E37A080,
0x33DB4D1E, 0x2D07225F, 0x0E63939C, 0x10BFFCDD, 0x48AAF01A, 0x56769F5B, 0x75122E98, 0x6BCE41D9,
0xC5383716, 0xDBE45857, 0xF880E994, 0xE65C86D5, 0xBE498A12, 0xA095E553, 0x83F15490, 0x9D2D3BD1,
0x38288FAC, 0x26F4E0ED, 0x0590512E, 0x1B4C3E6F, 0x435932A8, 0x5D855DE9, 0x7EE1EC2A, 0x603D836B,
0xCECBF5A4, 0xD0179AE5, 0xF3732B26, 0xEDAF4467, 0xB5BA48A0, 0xAB6627E1, 0x88029622, 0x96DEF963,
0xCB3214FD, 0xD5EE7BBC, 0xF68ACA7F, 0xE856A53E, 0xB043A9F9, 0xAE9FC6B8, 0x8DFB777B, 0x9327183A,
0x3DD16EF5, 0x230D01B4, 0x0069B077, 0x1EB5DF36, 0x46A0D3F1, 0x587CBCB0, 0x7B180D73, 0x65C46232,
0x2FCF0AC8, 0x31136589, 0x1277D44A, 0x0CABBB0B, 0x54BEB7CC, 0x4A62D88D, 0x6906694E, 0x77DA060F,
0xD92C70C0, 0xC7F01F81, 0xE494AE42, 0xFA48C103, 0xA25DCDC4, 0xBC81A285, 0x9FE51346, 0x81397C07,
0xDCD59199, 0xC209FED8, 0xE16D4F1B, 0xFFB1205A, 0xA7A42C9D, 0xB97843DC, 0x9A1CF21F, 0x84C09D5E,
0x2A36EB91, 0x34EA84D0, 0x178E3513, 0x09525A52, 0x51475695, 0x4F9B39D4, 0x6CFF8817, 0x7223E756,
0xD726532B, 0xC9FA3C6A, 0xEA9E8DA9, 0xF442E2E8, 0xAC57EE2F, 0xB28B816E, 0x91EF30AD, 0x8F335FEC,
0x21C52923, 0x3F194662, 0x1C7DF7A1, 0x02A198E0, 0x5AB49427, 0x4468FB66, 0x670C4AA5, 0x79D025E4,
0x243CC87A, 0x3AE0A73B, 0x198416F8, 0x075879B9, 0x5F4D757E, 0x41911A3F, 0x62F5ABFC, 0x7C29C4BD,
0xD2DFB272, 0xCC03DD33, 0xEF676CF0, 0xF1BB03B1, 0xA9AE0F76, 0xB7726037, 0x9416D1F4, 0x8ACABEB5,
};

static uint8_t
reflect8(uint8_t in)
{
	uint8_t out = 0;
	int i;

	for (i = 7; i >= 0; --i, in >>= 1)
		out |= (in & 0x1) << i;
	return out;
}

static uint32_t
reflect32(uint32_t in)
{
	uint32_t out = 0;
	int i;

	for (i = 31; i >= 0; --i, in >>= 1)
		out |= (in & 0x1) << i;
	return out;
}

static uint32_t
crc32(uint32_t seed, const uint8_t *src, uint64_t len, uint32_t flags)
{
	uint32_t crc;
	uint64_t i;
	uint8_t input, pos;
	bool bypass_data_ref = !!(flags & CRC_BYP_DATA_REF);
	bool bypass_crc_inv_ref = !!(flags & CRC_BYP_CRC_INV_REF);

	crc = bypass_crc_inv_ref ? seed : ~reflect32(seed);

	/**
	 * CRC calculation ref:
	 * www.sunshine2k.de/articles/coding/crc/understanding_crc.html
	 * CRC calculator:
	 * http://www.sunshine2k.de/coding/javascript/crc/crc_js.html
	 */
	for (i = 0; i < len; i++) {
		input = bypass_data_ref ? src[i] : reflect8(src[i]);
		pos = (crc >> 24) ^ input;
		crc = (crc << 8) ^ crc32_table[pos];
	}

	return bypass_crc_inv_ref ? crc : ~reflect32(crc);
}

static void
prep_dsa_copy_crc(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	int i;
	struct tcfg *tcfg = tcpu->tcfg;
	uint8_t *src = (uint8_t *)tcpu->src;

	prep_dsa_memmove(tcpu, desc);
	for (i = 0; i < tcfg->nb_bufs; i++) {
		tcpu->crc[i] = crc32(0, src, tcfg->blen, tcpu->tcfg->flags_smask);
		src += tcfg->bstride;
	}
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
shuffle_descs(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	struct dsa_hw_desc *pd = tcpu->desc;
	int i;

	if (!tcfg->shuffle_descs)
		return;

	for (i = tcfg->nb_bufs; i > 0; i--) {
		struct dsa_hw_desc t;
		int r = rand() % i;

		t = pd[i - 1];
		pd[i - 1] = pd[r];
		pd[r] = t;
	}
}

static void
test_prep_batch_desc(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg;
	struct dsa_hw_desc *desc;
	int i;
	void *bcomp = &tcpu->bcomp[0];

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
		desc->completion_addr = rte_mem_virt2iova(bcomp);
		PTR_ADD(bcomp, comp_rec_cache_aligned_size(tcpu));
	}
}

#define WR_FLAGS (IDXD_OP_FLAG_CC | IDXD_OP_FLAG_STORD)

void
test_prep_desc(struct tcfg_cpu *tcpu)
{
	struct tcfg *tcfg = tcpu->tcfg;
	unsigned int i;
	struct dsa_hw_desc desc = {}, *pd;
	uint32_t resv_flags[DSA_OPCODE_CFLUSH + 1] = {
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

	shuffle_descs(tcpu);

	for (i = 0; i < tcfg->nb_bufs; i++) {
		char *c;

		c = (char *)tcpu->comp + i * comp_rec_cache_aligned_size(tcpu);
		pd[i].completion_addr = rte_mem_virt2iova(c);

		/* mmap(MAP_POPULATE) but generates a fault on write after fork */
		if (tcfg->pg_size == 0 && tcfg->proc)
			faultin_range((char *)(pd[i].completion_addr & ~0xfffUL),
				4096, 4096, 1);
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
