/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Main Secure Launch header file.
 *
 * Copyright (c) 2022, Oracle and/or its affiliates.
 */

#ifndef _LINUX_SLAUNCH_H
#define _LINUX_SLAUNCH_H

/*
 * Secure Launch Defined State Flags
 */
#define SL_FLAG_ACTIVE		0x00000001
#define SL_FLAG_ARCH_SKINIT	0x00000002
#define SL_FLAG_ARCH_TXT	0x00000004

/*
 * Secure Launch CPU Type
 */
#define SL_CPU_AMD	1
#define SL_CPU_INTEL	2

#if IS_ENABLED(CONFIG_SECURE_LAUNCH)

/*
 * Intel Safer Mode Extensions (SMX)
 *
 * Intel SMX provides a programming interface to establish a Measured Launched
 * Environment (MLE). The measurement and protection mechanisms supported by the
 * capabilities of an Intel Trusted Execution Technology (TXT) platform. SMX is
 * the processor’s programming interface in an Intel TXT platform.
 *
 * See Intel SDM Volume 2 - 6.1 "Safer Mode Extensions Reference"
 */

/*
 * SMX GETSEC Leaf Functions
 */
#define SMX_X86_GETSEC_SEXIT	5
#define SMX_X86_GETSEC_SMCTRL	7
#define SMX_X86_GETSEC_WAKEUP	8

/*
 * Intel Trusted Execution Technology MMIO Registers Banks
 */
#define TXT_PUB_CONFIG_REGS_BASE	0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE	0xfed20000
#define TXT_NR_CONFIG_PAGES     ((TXT_PUB_CONFIG_REGS_BASE - \
				  TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

/*
 * Intel Trusted Execution Technology (TXT) Registers
 */
#define TXT_CR_STS			0x0000
#define TXT_CR_ESTS			0x0008
#define TXT_CR_ERRORCODE		0x0030
#define TXT_CR_CMD_RESET		0x0038
#define TXT_CR_CMD_CLOSE_PRIVATE	0x0048
#define TXT_CR_DIDVID			0x0110
#define TXT_CR_VER_EMIF			0x0200
#define TXT_CR_CMD_UNLOCK_MEM_CONFIG	0x0218
#define TXT_CR_SINIT_BASE		0x0270
#define TXT_CR_SINIT_SIZE		0x0278
#define TXT_CR_MLE_JOIN			0x0290
#define TXT_CR_HEAP_BASE		0x0300
#define TXT_CR_HEAP_SIZE		0x0308
#define TXT_CR_SCRATCHPAD		0x0378
#define TXT_CR_CMD_OPEN_LOCALITY1	0x0380
#define TXT_CR_CMD_CLOSE_LOCALITY1	0x0388
#define TXT_CR_CMD_OPEN_LOCALITY2	0x0390
#define TXT_CR_CMD_CLOSE_LOCALITY2	0x0398
#define TXT_CR_CMD_SECRETS		0x08e0
#define TXT_CR_CMD_NO_SECRETS		0x08e8
#define TXT_CR_E2STS			0x08f0

/* TXT default register value */
#define TXT_REGVALUE_ONE		0x1ULL

/* TXTCR_STS status bits */
#define TXT_SENTER_DONE_STS		BIT(0)
#define TXT_SEXIT_DONE_STS		BIT(1)

#ifndef __ASSEMBLY__

/*
 * External functions avalailable in mainline kernel.
 */
u32 slaunch_get_flags(void);
void __noreturn slaunch_txt_reset(void __iomem *txt,
				 const char *msg, u64 error);
extern void slaunch_finalize(int do_sexit);

#endif /* !__ASSEMBLY */

#else

static inline u32 slaunch_get_flags(void)
{
	return 0;
}

static inline void slaunch_finalize(int do_sexit)
{
}

#endif /* !IS_ENABLED(CONFIG_SECURE_LAUNCH) */

#endif /* _LINUX_SLAUNCH_H */
