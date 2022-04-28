/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Secure Launch dynamic launch event support.
 *
 * Copyright (c) 2022, Oracle and/or its affiliates.
 */
	.code32
	.text
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/page_types.h>
#include <asm/apicdef.h>
#include <linux/drtm_table.h>
#include <linux/slaunch.h>

/* Can't include apiddef.h in asm */
#define XAPIC_ENABLE	(1 << 11)
#define X2APIC_ENABLE	(1 << 10)

#define rva(X) ((X) - dynamic_launch_event)

	.code64
SYM_FUNC_START(dynamic_launch_event)
	/*
	 * On entry:
	 * - %rdi has the architecture type for the DLE
	 * - %rsi has the DCE physical address
	 * - %rdx has the DCE size
	 */

	/* While still in long mode, have a stack to find ourselves with */
	call	1f
1:	popq	%rbx
	subq	$rva(1b), %rbx


	/* Load GDT for protected mode, still using existing long mode GDT */
	leal	rva(dl_gdt_desc)(%ebx), %eax
	addl	%eax, 2(%eax)
	lgdt	(%eax)

	/* Return to protected mode, paging off */
	leal	1f(%rip), %ecx
	pushq	$__SL32_CS
	pushq	%rcx
	lretq

	.code32
1:	/* Now in IA-32e compatibility mode, next stop is protected mode */
	cld
	cli

	/* Load known data segment descritor */
	movl	$__SL32_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss

	/* Turn paging off - we are identity mapped so we will survive */
	movl	%cr0, %eax
	andl	$~(CR0_PG | CR0_NE | CR0_TS | CR0_MP), %eax
	movl	%eax, %cr0

	/* Disable IA-32e mode */
	movl	$IA32_EFER, %ecx
	rdmsr
	andb	$~(EFER_LME >> 8), %ah
	wrmsr

	/* Now in protected mode, prepare pre-launch CPU */
	movl	%cr0, %eax
	/* Disable cache */
	andl	$~CR0_CD, %eax
	andl	$~CR0_NW, %eax
	/* Native FPU error reporting must be enabled */
	orl	CR0_NE, %eax
	movl	%eax, %cr0

	/* Disable virtual-8086 mode just in case */
	leal	rva(dl_stack_end)(%ebx), %esp
	pushfl
	popl	%eax
	andl	~$(X86_EFLAGS_VM), %eax
	pushl	%eax
	popfl

	/* MCE setup was done in the bootloader preamble code */

	/* The DL Event */
	testl	$(DRTM_INTEL_TXT), %edi
	jz	.Ldie /* AMD/SKINIT support here yet */

	/* Intel/TXT GETSEC[SENTER] */
	movl	$(SMX_X86_GETSEC_SENTER), %eax
	movl	%edi, %ebx
	movl	%edx, %ecx
	xorl	%edx, %edx
	.byte 	0x0f, 0x37	/* GETSEC opcode */

.Ldie:
	ud2
SYM_FUNC_END(dynamic_launch_event)

	.data
	.balign 8
SYM_DATA_START_LOCAL(dl_gdt_desc)
	.word	dl_gdt_end - dl_gdt - 1
	.long	dl_gdt - dl_gdt_desc
SYM_DATA_END_LABEL(dl_gdt_desc, SYM_L_LOCAL, dl_gdt_desc_end)

	.balign	8
SYM_DATA_START_LOCAL(dl_gdt)
	.quad	0x0000000000000000	/* NULL */
	.quad	0x00cf9a000000ffff	/* __SL32_CS */
	.quad	0x00cf92000000ffff	/* __SL32_DS */
SYM_DATA_END_LABEL(dl_gdt, SYM_L_LOCAL, dl_gdt_end)

	.balign 4
SYM_DATA_START_LOCAL(dl_stack)
	.fill 4, 1, 0
SYM_DATA_END_LABEL(dl_scratch_stack, SYM_L_LOCAL, dl_stack_end)

SYM_DATA(dl_apic_base, .long 0x00000000)

