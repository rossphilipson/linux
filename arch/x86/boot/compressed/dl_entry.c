// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch dynamic launch event support.
 *
 * Copyright (c) 2022, Oracle and/or its affiliates.
 */

#include <linux/init.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <linux/efi.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/mtrr.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/mtrr.h>
#include <asm/bitops.h>
#include <asm/efi.h>
#include <asm/bootparam_utils.h>
#include <linux/slr_table.h>
#include <linux/slaunch.h>

#define SL_ACM_MTRR_MASK	0xffffff  /* ACM requires 36b mask */

#define MTRR_DEF_ENABLE_FIXED	(1<<10)
#define MTRR_DEF_ENABLE_ALL	(1<<11)

#define MTRR_CAP_VCNT_MASK	0xff

#define MTRR_PHYS_MASK_VALID	(1<<11)

#define MTRR_MEMTYPE_MASK	0xff
#define MTRR_PHYSBASE_SHIFT	12
#define MTRRphysBaseVal(b)	(((b >> PAGE_SHIFT) & SL_ACM_MTRR_MASK) \
				<< MTRR_PHYSBASE_SHIFT)
#define MTRR_VALID_BIT		(1<<11)
#define MTRR_PHYSMASK_SHIFT	12
#define MTRRphysMaskVal(r)	((~(r - 1) & SL_ACM_MTRR_MASK) \
				<< MTRR_PHYSMASK_SHIFT)

extern void __noreturn dynamic_launch_event(u64 architecture,
					    u64 dce_phys_addr,
					    u64 dce_size);

static inline void dl_reset(void)
{
	asm volatile ("ud2");
}

static inline unsigned long dl_read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val));
	return val;
}

static inline void dl_write_cr0(unsigned long val)
{
	asm volatile("mov %0,%%cr0\n\t" : : "r" (val));
}

static inline unsigned long dl_read_cr4(void)
{
	unsigned long val;
	asm volatile("mov %%cr4,%0\n\t" : "=r" (val));
	return val;
}

static inline void dl_write_cr4(unsigned long val)
{
	asm volatile("mov %0,%%cr4\n\t" : : "r" (val));
}

static void dl_txt_setup_acm_mtrrs(u64 base, u32 size)
{
	/* Types might be different in Linux */
	u64 msr, mtrr_max_range, mtrr_next_range;
	u32 base_bsf, vcnt, npages, i, j, n = 0;

	msr = sl_rdmsr(MSR_MTRRcap);
	vcnt = (msr & MTRR_CAP_VCNT_MASK);
	for (i = 0; i < vcnt; i++) {
		msr = sl_rdmsr(MTRRphysMask_MSR(i));
		msr &= ~(MTRR_PHYS_MASK_VALID);
		sl_wrmsr(MTRRphysMask_MSR(i), msr);
	}

	/*
	 * There are very specific rules about calculating the MTRR mask.
	 * If the size of the range is a power of 2 and the base of the range
	 * is on a size of range boundary, a single MTRR can be used. In all
	 * other cases multiple MTRRs must be used. Depending on the base and
	 * size, this could end up being successively smaller MTRR range sizes
	 * but they all have to be multiples of one another.
	 */

	/* Bit shift forward the base to determine the max MTRR range to use */
	base_bsf = (u32)base;
	mtrr_max_range = 1;
	i = 0;

	while ((base_bsf & 0x01) == 0) {
		i++;
		base_bsf = base_bsf >> 1;
	}

	for (j = i - 12; j > 0; j--)
		mtrr_max_range = mtrr_max_range << 1;

	npages = ((size + PAGE_SIZE - 1) & PAGE_MASK) >> PAGE_SHIFT;

	/* First loop, set up MTRR ranges using the max range */
 	while (npages >= mtrr_max_range) {
		msr = sl_rdmsr(MTRRphysBase_MSR(n));
		msr |= MTRRphysBaseVal(base);
		msr |= (MTRR_TYPE_WRBACK & MTRR_MEMTYPE_MASK);
		sl_wrmsr(MTRRphysBase_MSR(n), msr);

		msr = sl_rdmsr(MTRRphysMask_MSR(n));
		msr |= MTRRphysMaskVal(mtrr_max_range);
		msr |= MTRR_VALID_BIT;
		sl_wrmsr(MTRRphysMask_MSR(n), msr);

		n++;
		npages -= mtrr_max_range;
		base += (mtrr_max_range * PAGE_SIZE);

		if (n == vcnt)
			dl_reset();
	}

	/* Second loop, setup successively smaller ranges to cover the rest */
	while (npages > 0) {
		/*
		 * Calculate next range using find first set bit. This will start
		 * yielding smaller ranges, all multibles of 2, until the rest of
		 * the ACM range is all covered.
		 */
		if (!mtrr_next_range)
			dl_reset();

		mtrr_next_range = 1 << (__fls(npages) - 1);

		msr = sl_rdmsr(MTRRphysBase_MSR(n));
		msr |= MTRRphysBaseVal(base);
		msr |= (MTRR_TYPE_WRBACK & MTRR_MEMTYPE_MASK);
		sl_wrmsr(MTRRphysBase_MSR(n), msr);

		msr = sl_rdmsr(MTRRphysMask_MSR(n));
		msr |= MTRRphysMaskVal(mtrr_next_range);
		msr |= MTRR_VALID_BIT;
		sl_wrmsr(MTRRphysMask_MSR(n), msr);

		n++;
		npages -= mtrr_next_range;
		base += (mtrr_next_range * PAGE_SIZE);

		if (n == vcnt)
			dl_reset();
	}
}

static void dl_txt_setup_mtrrs(struct slr_entry_dl_info *dl_info)
{
	unsigned long cr0, cr4, msr;

	/* Disable interrupts and caching */
	native_irq_disable();

	cr0 = dl_read_cr0();
	dl_write_cr0((cr0 & ~X86_CR0_NW) | X86_CR0_CD); /* CRO.NW=0 CRO.CD=1 */

	/* Now flush all caches and disable global pages */
	native_wbinvd();

	cr4 = dl_read_cr4();
	dl_write_cr4(cr4 & ~X86_CR4_PGE);

	/* Disable all MTRRs */
	msr = sl_rdmsr(MSR_MTRRdefType);
	sl_wrmsr(MSR_MTRRdefType, msr & ~MTRR_DEF_ENABLE_ALL);

	/* Setup ACM MTRRs as WB, rest of the world is UC, fixed MTRRs off */
	msr = sl_rdmsr(MSR_MTRRdefType);
	msr &= ~MTRR_DEF_ENABLE_FIXED;
	msr |= (MTRR_TYPE_UNCACHABLE & 0xff);
	sl_wrmsr(MSR_MTRRdefType, msr);

	/* Map the ACM */
	dl_txt_setup_acm_mtrrs(dl_info->dce_base, dl_info->dce_size);

	/* Flush all caches again and enable all MTRRs */
	native_wbinvd();

	msr = sl_rdmsr(MSR_MTRRdefType);
	sl_wrmsr(MSR_MTRRdefType, msr | MTRR_DEF_ENABLE_ALL);

	/* Restore control registers */
	dl_write_cr0(cr0);
	dl_write_cr4(cr4);

	/* Reenable interrupts */
	native_irq_enable();
}

void dl_stub_entry(struct slr_table *slr_table)
{
	struct slr_entry_dl_info *dl_info;

	dl_info = (struct slr_entry_dl_info *)
		slr_next_entry_by_tag(slr_table, NULL, SLR_ENTRY_DL_INFO);
	if (!dl_info)
		dl_reset();

	if (!dl_info->dce_base || !dl_info->dce_size)
		dl_reset();

	if (slr_table->architecture == SLR_INTEL_TXT) {
		/*
		 * Set ACM memory to WB and all other to UC. Note all
		 * MTRRs have been saved in the TXT heap for restoration
		 * after SENTER
		 */
		dl_txt_setup_mtrrs(dl_info);
	} else {
		/* AMD support not present yet */
		dl_reset();
	}

	/* Final entry into dynamic launch event code */
	dynamic_launch_event(slr_table->architecture,
			     dl_info->dce_base,
			     dl_info->dce_size);

	unreachable();
}
