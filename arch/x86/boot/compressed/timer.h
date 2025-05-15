/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BOOT_COMPRESSED_MISC_H
#define BOOT_COMPRESSED_MISC_H

/* Calibrate CPU hz with PIT running at known clock frequency */
void pit_calibrate(void);

/* Timer functions */
void mdelay(u32 ms);
void udelay(u32 us);

#endif /* BOOT_COMPRESSED_MISC_H */
