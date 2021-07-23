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

static const uint32_t crc32_table[256] = {
0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b, 0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b, 0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a, 0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5, 0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a, 0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687, 0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927, 0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096, 0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859, 0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9, 0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36, 0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c, 0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043, 0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3, 0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c, 0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652, 0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d, 0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530, 0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff, 0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f, 0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90, 0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee, 0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321, 0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81, 0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e, 0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351,
};

static uint32_t crc32(uint32_t crc, const uint8_t *src, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len; i++) {
		uint8_t tmp = src[i];

		crc = crc32_table[(crc ^ tmp) & 0xff] ^ (crc >> 8);
	}

	return crc;
}

static void
prep_dsa_copy_crc(struct tcfg_cpu *tcpu, struct dsa_hw_desc *desc)
{
	int i;
	struct tcfg *tcfg = tcpu->tcfg;
	uint8_t *src = (uint8_t *)tcpu->src;

	prep_dsa_memmove(tcpu, desc);
	for (i = 0; i < tcfg->nb_bufs; i++) {
		tcpu->crc[i] = ~crc32(~0, src, tcfg->blen);
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
