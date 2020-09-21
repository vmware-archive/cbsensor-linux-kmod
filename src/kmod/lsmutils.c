/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// N.B. You cannot call these from within hooks.c locks!!!
//
// Get Path from dentry
//
// Get Path from file *
//
// Get Path from inode *
#define DS_MYSUBSYS DS_LSM
#include "priv.h"
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/utsname.h>

// Callback fn for kallsyms_on_each_symbol
static int allsyms_find_symbol(void *data, const char *symstr,
			       struct module *module, unsigned long address)
{
	struct symbol_list *list = (struct symbol_list *)data;
	struct symbols_s *curr_symbol;

	if (!list) {
		return 0;
	}

	// Exit callback function sooner
	if (list->count >= list->size) {
		return 0;
	}

	for (curr_symbol = list->symbols; curr_symbol && curr_symbol->name;
	     ++curr_symbol) {
		// Skip if found
		if (*curr_symbol->addr) {
			continue;
		}

		if (strcmp(symstr, curr_symbol->name) == 0) {
			list->count += 1;
			*curr_symbol->addr = address;
			break;
		}
	}
	return 0;
}

//
// Primarily used to find private symbols
//
void lookup_symbols(struct symbol_list *sym_list)
{
	if (sym_list) {
		// Clear out global struct containing static mappings of
		// symbols to resolved addresses.
		memset(&g_resolvedSymbols, 0, sizeof(g_resolvedSymbols));
		kallsyms_on_each_symbol(allsyms_find_symbol, sym_list);
	}
}

struct linuxSpinlock {
	spinlock_t sp;
	pid_t create_pid;
	pid_t owner_pid;
	unsigned long flags;
};

#define USE_BH 1
#define USE_IRQ 2
#define SPINLOCK_TYPE USE_IRQ

void cb_initspinlock(uint64_t *sp)
{
	struct linuxSpinlock *new_spinlock = (struct linuxSpinlock *)kmalloc(
		sizeof(struct linuxSpinlock), GFP_KERNEL);

	if (new_spinlock) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		spin_lock_init(&new_spinlock->sp);
#else
		new_spinlock->sp = SPIN_LOCK_UNLOCKED;
#endif
		new_spinlock->create_pid = gettid(current);
		new_spinlock->owner_pid = 0;
		new_spinlock->flags = 0;
		*sp = (uint64_t)new_spinlock;
	} else {
		PRINTK(KERN_WARNING, "failed initialize spinlock pid=%d",
		       gettid(current));
		*sp = 0;
	}
}

void cb_spinlock(const uint64_t *sp)
{
	struct linuxSpinlock *spinlockp = (struct linuxSpinlock *)*sp;
	pid_t tid = gettid(current);

#ifdef DEADLOCK_DBG
	if (spinlockp->owner_pid == tid && spin_is_locked(&spinlockp->sp)) {
		PRINTK(KERN_WARNING, "already LOCKED pid=%d owner=%d", tid,
		       spinlockp->owner_pid);
	}
#endif

#if SPINLOCK_TYPE == USE_IRQ
	spin_lock_irqsave(&spinlockp->sp, spinlockp->flags);
#elif SPINLOCK_TYPE == USE_BH
	spin_lock_bh(&spinlockp->sp);
#endif

	if (spinlockp->owner_pid == 0) {
		spinlockp->owner_pid = tid;
	}
}

void cb_spinunlock(const uint64_t *sp)
{
	struct linuxSpinlock *spinlockp = (struct linuxSpinlock *)*sp;

#ifdef DEADLOCK_DBG
	if ((spinlockp->owner_pid != 0 &&
	     spinlockp->owner_pid != gettid(current)) ||
	    !spin_is_locked(&spinlockp->sp)) {
		PRINTK(KERN_WARNING, "already UNLOCKED pid=%d owner=%d",
		       gettid(current), spinlockp->owner_pid);
	}
#endif

	spinlockp->owner_pid = 0;
#if SPINLOCK_TYPE == USE_IRQ
	spin_unlock_irqrestore(&spinlockp->sp, spinlockp->flags);
#elif SPINLOCK_TYPE == USE_BH
	spin_unlock_bh(&spinlockp->sp);
#endif
}

void cb_destroyspinlock(const uint64_t *sp)
{
	struct linuxSpinlock *spinlockp = (struct linuxSpinlock *)*sp;
#ifdef DEADLOCK_DBG
	if (spin_is_locked(&spinlockp->sp)) {
		PRINTK(KERN_WARNING,
		       "LOCKED and being destroyed pid=%d owner=%d",
		       gettid(current), spinlockp->owner_pid);
	}
#endif
	kfree((struct linuxSpinlock *)spinlockp);
}
