// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch early measurement and validation routines.
 *
 * Copyright (c) 2025, Oracle and/or its affiliates.
 */

#include <linux/init.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/bootparam_utils.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>

void __cold __noreturn __fortify_panic(const u8 reason, const size_t avail, const size_t size)
{
	asm volatile ("ud2");

	unreachable();
}

asmlinkage __visible void sl_main(void *bootparams)
{
	struct boot_params *bp  = (struct boot_params *)bootparams;

	/* TODO this is just test framework running in the correct context */
}
