/* Copyright (C) IBM Corporation, 2013
 *
 *
 * Generic code for enabling ELI shadow-idt
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <asm/apic.h>

#define DI_INITIALIZE 300

static void *shadow_idt;

static int eli_init(void)
{
	shadow_idt = kzalloc(PAGE_SIZE, GFP_ATOMIC);
	asm volatile("vmcall" : /* no output */ : "a"(DI_INITIALIZE), "b"(shadow_idt));


	return 0;
}


static void eli_exit(void)
{
	kfree(shadow_idt);
}

module_init(eli_init);
module_exit(eli_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("ExtiLess Interrupts (ELI) guest kernel accelerator");

