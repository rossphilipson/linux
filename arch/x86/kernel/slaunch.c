// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch late validation/setup and finalization support.
 *
 * Copyright (c) 2022, Oracle and/or its affiliates.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/linkage.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <linux/memblock.h>
#include <asm/segment.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/e820/api.h>
#include <asm/setup.h>
#include <asm/realmode.h>
#include <linux/slaunch.h>

static u32 sl_flags __ro_after_init;

/*
 * Get the Secure Launch flags that indicate what kind of launch is being done.
 * E.g. a TXT launch is in progress or no Secure Launch is happening.
 */
u32 slaunch_get_flags(void)
{
	return sl_flags;
}

/*
 * If running within a TXT established DRTM, this is the proper way to reset
 * the system if a failure occurs or a security issue is found.
 */
void __noreturn slaunch_txt_reset(void __iomem *txt,
				  const char *msg, u64 error)
{
	u64 one = 1, val;

	pr_err("%s", msg);

	/*
	 * This performs a TXT reset with a sticky error code. The reads of
	 * TXT_CR_E2STS act as barriers.
	 */
	memcpy_toio(txt + TXT_CR_ERRORCODE, &error, sizeof(error));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));
	memcpy_toio(txt + TXT_CR_CMD_NO_SECRETS, &one, sizeof(one));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));
	memcpy_toio(txt + TXT_CR_CMD_UNLOCK_MEM_CONFIG, &one, sizeof(one));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));
	memcpy_toio(txt + TXT_CR_CMD_RESET, &one, sizeof(one));

	for ( ; ; )
		asm volatile ("hlt");

	unreachable();
}

static inline void smx_getsec_sexit(void)
{
	asm volatile (".byte 0x0f,0x37\n"
		      : : "a" (SMX_X86_GETSEC_SEXIT));
}

/*
 * Used during kexec and on reboot paths to finalize the TXT state
 * and do an SEXIT exiting the DRTM and disabling SMX mode.
 */
void slaunch_finalize(int do_sexit)
{
	u64 one = TXT_REGVALUE_ONE, val;
	void __iomem *config;

	/*if ((slaunch_get_flags() & (SL_FLAG_ACTIVE | SL_FLAG_ARCH_TXT)) !=
	    (SL_FLAG_ACTIVE | SL_FLAG_ARCH_TXT))
		return;*/

	config = ioremap(TXT_PRIV_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_emerg("***RJP*** Error SEXIT failed to ioremap TXT private reqs\n");
		return;
	}

	/* Clear secrets bit for SEXIT */
	memcpy_toio(config + TXT_CR_CMD_NO_SECRETS, &one, sizeof(one));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	/* Unlock memory configurations */
	memcpy_toio(config + TXT_CR_CMD_UNLOCK_MEM_CONFIG, &one, sizeof(one));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	/* Close the TXT private register space */
	memcpy_toio(config + TXT_CR_CMD_CLOSE_PRIVATE, &one, sizeof(one));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	/*
	 * Calls to iounmap are not being done because of the state of the
	 * system this late in the kexec process. Local IRQs are disabled and
	 * iounmap causes a TLB flush which in turn causes a warning. Leaving
	 * thse mappings is not an issue since the next kernel is going to
	 * completely re-setup memory management.
	 */

	/* Map public registers and do a final read fence */
	config = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_emerg("***RJP*** Error SEXIT failed to ioremap TXT public reqs\n");
		return;
	}

	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	pr_emerg("***RJP*** TXT clear secrets bit and unlock memory complete.\n");

	if (!do_sexit)
		return;

	if (smp_processor_id() != 0)
		panic("***RJP*** Error TXT SEXIT must be called on CPU 0\n");

	/* Disable SMX mode */
	cr4_set_bits(X86_CR4_SMXE);

	/* Do the SEXIT SMX operation */
	smx_getsec_sexit();

	pr_info("***RJP*** TXT SEXIT complete.\n");
}
