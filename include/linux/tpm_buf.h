/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TODO copyright etc?
 *
 * Device driver for TCG/TCPA TPM (trusted platform module).
 * Specifications at www.trustedcomputinggroup.org
 */
#ifndef __LINUX_TPM_BUF_H__
#define __LINUX_TPM_BUF_H__

enum tpm_buf_flags {
	/* the capacity exceeded: */
	TPM_BUF_OVERFLOW	= BIT(0),
	/* TPM2B format: */
	TPM_BUF_TPM2B		= BIT(1),
	/* read out of boundary: */
	TPM_BUF_BOUNDARY_ERROR	= BIT(2),
};

/*
 * A string buffer type for constructing TPM commands.
 */
struct tpm_buf {
	u32 flags;
	u32 length;
	u8 *data;
	u8 handles;
};

int tpm_buf_init(struct tpm_buf *buf, u16 tag, u32 ordinal);
void tpm_buf_reset(struct tpm_buf *buf, u16 tag, u32 ordinal);
int tpm_buf_init_sized(struct tpm_buf *buf);
void tpm_buf_reset_sized(struct tpm_buf *buf);
void tpm_buf_destroy(struct tpm_buf *buf);
u32 tpm_buf_length(struct tpm_buf *buf);
void tpm_buf_append(struct tpm_buf *buf, const u8 *new_data, u16 new_length);
void tpm_buf_append_u8(struct tpm_buf *buf, const u8 value);
void tpm_buf_append_u16(struct tpm_buf *buf, const u16 value);
void tpm_buf_append_u32(struct tpm_buf *buf, const u32 value);
u8 tpm_buf_read_u8(struct tpm_buf *buf, off_t *offset);
u16 tpm_buf_read_u16(struct tpm_buf *buf, off_t *offset);
u32 tpm_buf_read_u32(struct tpm_buf *buf, off_t *offset);
bool tpm_buf_append_handle(struct tpm_buf *buf, u32 handle);

#endif
