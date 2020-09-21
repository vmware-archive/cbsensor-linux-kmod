/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// Linux Syscall Hook Helpers

#define DS_MYSUBSYS (DS_HOOK)
#include "priv.h"
#include "syscall_stub.h"

#include <linux/unistd.h>

// For the fork/clone hooks
extern void *CBSYSSTUB_NAME(clone)(void);
extern void *CBSYSSTUB_NAME(fork)(void);
extern void *CBSYSSTUB_NAME(vfork)(void);

// Asm hooks to original syscalls
extern void *ORIG_SYSCALL_PTR(clone);
extern void *ORIG_SYSCALL_PTR(fork);
extern void *ORIG_SYSCALL_PTR(vfork);

// For network hooks
extern long (*cb_orig_sys_recvfrom)(int, void __user *, size_t, unsigned,
				    struct sockaddr __user *, int __user *);
extern long (*cb_orig_sys_recvmsg)(int fd, struct msghdr __user *msg,
				   unsigned flags);
extern long (*cb_orig_sys_recvmmsg)(int fd, struct mmsghdr __user *msg,
				    unsigned int vlen, unsigned flags,
				    struct timespec __user *timeout);

extern asmlinkage long cb_sys_recvfrom(int fd, void __user *ubuf, size_t size,
				       unsigned flags,
				       struct sockaddr __user *addr,
				       int __user *addr_len);
extern asmlinkage long cb_sys_recvmsg(int fd, struct msghdr __user *msg,
				      unsigned flags);
extern asmlinkage long cb_sys_recvmmsg(int fd, struct mmsghdr __user *msg,
				       unsigned int vlen, unsigned flags,
				       struct timespec __user *timeout);

// For File hooks
extern long (*cb_orig_sys_write)(unsigned int fd, const char __user *buf,
				 size_t count);

extern asmlinkage long cb_sys_write(unsigned int fd, const char __user *buf,
				    size_t count);

// Kernel module hooks
extern long (*cb_orig_sys_delete_module)(const char __user *name_user,
					 unsigned int flags);

extern asmlinkage long cb_sys_delete_module(const char __user *name_user,
					    unsigned int flags);

extern uint32_t g_enableHooks;

static unsigned long page_rw_set;
static uint64_t page_rw_lock = 0;

static inline pte_t *lookup_pte(p_sys_call_table address)
{
	unsigned int level;
	TRY_CB_RESOLVED(lookup_address);
	return CB_RESOLVED(lookup_address)((unsigned long)address, &level);

CATCH_DEFAULT:
	return NULL;
}

static inline bool set_page_state_rw(p_sys_call_table address)
{
	pte_t *pte = lookup_pte(address);
	if (!pte)
		return false;

	cb_spinlock(&page_rw_lock);
	page_rw_set = pte->pte & _PAGE_RW;
	pte->pte |= _PAGE_RW;

	return true;
}

static inline void restore_page_state(p_sys_call_table address)
{
	pte_t *pte = lookup_pte(address);
	if (!pte) {
		cb_spinunlock(&page_rw_lock);
		return;
	}

	// If the page state was originally RO, restore it to RO.
	// We don't just assign the original value back here in case some other
	// bits were changed.
	if (!page_rw_set)
		pte->pte &= ~_PAGE_RW;
	cb_spinunlock(&page_rw_lock);
}

static void save_old_hooks(p_sys_call_table syscall_table)
{
	cb_orig_sys_delete_module = syscall_table[__NR_delete_module];
	ORIG_SYSCALL_PTR(clone) = syscall_table[__NR_clone];
	ORIG_SYSCALL_PTR(fork) = syscall_table[__NR_fork];
	ORIG_SYSCALL_PTR(vfork) = syscall_table[__NR_vfork];
	cb_orig_sys_recvfrom = syscall_table[__NR_recvfrom];
	cb_orig_sys_recvmsg = syscall_table[__NR_recvmsg];
	cb_orig_sys_recvmmsg = syscall_table[__NR_recvmmsg];
	cb_orig_sys_write = syscall_table[__NR_write];
}

static bool set_new_hooks(p_sys_call_table syscall_table, uint32_t enableHooks)
{
	bool rval = false;

	// Disable CPU write protect, and update the call table after disabling
	// preemption for this cpu
	get_cpu();
	GPF_DISABLE;

	if (set_page_state_rw(syscall_table)) {
		if (enableHooks & CB__NR_delete_module)
			syscall_table[__NR_delete_module] =
				cb_sys_delete_module;
		/* The logic below sets up syscall hooks to handle process forks
		   Unlike in the LSM based logic, this hook will be called very
		   early in the fork process.  This runs in the context of the
		   FORKING process immediately after the child is started.  This
		   guarantees that we will have the correct parent pid.
		*/
		if (enableHooks & CB__NR_clone)
			syscall_table[__NR_clone] = CBSYSSTUB_NAME(clone);
		if (enableHooks & CB__NR_fork)
			syscall_table[__NR_fork] = CBSYSSTUB_NAME(fork);
		if (enableHooks & CB__NR_vfork)
			syscall_table[__NR_vfork] = CBSYSSTUB_NAME(vfork);
		if (enableHooks & CB__NR_recvfrom)
			syscall_table[__NR_recvfrom] = cb_sys_recvfrom;
		if (enableHooks & CB__NR_recvmsg)
			syscall_table[__NR_recvmsg] = cb_sys_recvmsg;
		if (enableHooks & CB__NR_recvmmsg)
			syscall_table[__NR_recvmmsg] = cb_sys_recvmmsg;
		if (enableHooks & CB__NR_write)
			syscall_table[__NR_write] = cb_sys_write;
		restore_page_state(syscall_table);
		rval = true;
	} else {
		PRINTK(KERN_ERR, "Failed to make 64-bit call table RW!!");
	}

	GPF_ENABLE;
	put_cpu();

	return rval;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static bool set_new_32bit_hooks(p_sys_call_table syscall_table,
				uint32_t enableHooks)
{
	bool rval = false;

	get_cpu();
	GPF_DISABLE;

	if (set_page_state_rw(syscall_table)) {
		if (enableHooks & CB__NR_write)
			syscall_table[__NR_ia32_write] = cb_sys_write;
		restore_page_state(syscall_table);
		rval = true;
	} else {
		PRINTK(KERN_ERR, "Failed to make 32-bit call table RW!!");
	}

	GPF_ENABLE;
	put_cpu();

	return rval;
}
#endif

static void restore_hooks(p_sys_call_table syscall_table, uint32_t enableHooks)
{
	// Disable CPU write protect, and restore the call table
	get_cpu();
	GPF_DISABLE;

	if (set_page_state_rw(syscall_table)) {
		if (enableHooks & CB__NR_clone)
			syscall_table[__NR_clone] = ORIG_SYSCALL_PTR(clone);
		if (enableHooks & CB__NR_fork)
			syscall_table[__NR_fork] = ORIG_SYSCALL_PTR(fork);
		if (enableHooks & CB__NR_vfork)
			syscall_table[__NR_vfork] = ORIG_SYSCALL_PTR(vfork);
		if (enableHooks & CB__NR_recvfrom)
			syscall_table[__NR_recvfrom] = cb_orig_sys_recvfrom;
		if (enableHooks & CB__NR_recvmsg)
			syscall_table[__NR_recvmsg] = cb_orig_sys_recvmsg;
		if (enableHooks & CB__NR_recvmmsg)
			syscall_table[__NR_recvmmsg] = cb_orig_sys_recvmmsg;
		if (enableHooks & CB__NR_write)
			syscall_table[__NR_write] = cb_orig_sys_write;
		if (enableHooks & CB__NR_delete_module)
			syscall_table[__NR_delete_module] =
				cb_orig_sys_delete_module;
		restore_page_state(syscall_table);
	} else {
		PRINTK(KERN_ERR, "Failed to make 64-bit call table RW!!");
	}

	GPF_ENABLE;
	put_cpu();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void restore_32bit_hooks(p_sys_call_table syscall_table,
				uint32_t enableHooks)
{
	// Disable CPU write protect, and restore the call table
	get_cpu();
	GPF_DISABLE;

	if (set_page_state_rw(syscall_table)) {
		if (enableHooks & CB__NR_write)
			syscall_table[__NR_ia32_write] = cb_orig_sys_write;
		restore_page_state(syscall_table);
	} else {
		PRINTK(KERN_ERR, "Failed to make 32-bit call table RW!!");
	}

	GPF_ENABLE;
	put_cpu();
}
#endif

bool syscall_initialize(uint32_t enableHooks)
{
	bool rval = false;
	p_sys_call_table syscall_table;
	cb_initspinlock(&page_rw_lock);

	// If the hooks are not enabled, then no point in continuing.
	if (!(enableHooks & 0xFF))
		return true;

	// Find the syscall table addresses.
	if (!g_resolvedSymbols.sys_call_table) {
		PRINTK(KERN_ERR,
		       "Function pointer \"sys_call_table\" is NULL.");
		goto CATCH_DEFAULT;
	}
	syscall_table = CB_RESOLVED(sys_call_table);

	save_old_hooks(syscall_table);
	rval = set_new_hooks(syscall_table, enableHooks);

	// Handle special cases for 32-bit system calls.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	{
		p_sys_call_table syscall_table_i32;
		if (!g_resolvedSymbols.ia32_sys_call_table) {
			PRINTK(KERN_ERR,
			       "Function pointer \"ia32_sys_call_tables\" is NULL.");
			goto CATCH_DEFAULT;
		}
		syscall_table_i32 = CB_RESOLVED(ia32_sys_call_table);

		rval &= set_new_32bit_hooks(syscall_table_i32, enableHooks);
	}
#endif

CATCH_DEFAULT:
	return rval;
}

bool syscall_hooks_changed(uint32_t enableHooks)
{
	bool changed = false;
	p_sys_call_table syscall_table;

	TRY_CB_RESOLVED(sys_call_table);
	syscall_table = CB_RESOLVED(sys_call_table);

	if (enableHooks & CB__NR_delete_module)
		changed |= syscall_table[__NR_delete_module] !=
			   cb_sys_delete_module;
	if (enableHooks & CB__NR_clone)
		changed |= syscall_table[__NR_clone] != CBSYSSTUB_NAME(clone);
	if (enableHooks & CB__NR_fork)
		changed |= syscall_table[__NR_fork] != CBSYSSTUB_NAME(fork);
	if (enableHooks & CB__NR_vfork)
		changed |= syscall_table[__NR_vfork] != CBSYSSTUB_NAME(vfork);
	if (enableHooks & CB__NR_recvfrom)
		changed |= syscall_table[__NR_recvfrom] != cb_sys_recvfrom;
	if (enableHooks & CB__NR_recvmsg)
		changed |= syscall_table[__NR_recvmsg] != cb_sys_recvmsg;
	if (enableHooks & CB__NR_recvmmsg)
		changed |= syscall_table[__NR_recvmmsg] != cb_sys_recvmmsg;
	if (enableHooks & CB__NR_write)
		changed |= syscall_table[__NR_write] != cb_sys_write;

CATCH_DEFAULT:
	return changed;
}

void syscall_shutdown(uint32_t enableHooks)
{
	p_sys_call_table syscall_table;

	TRY_CB_RESOLVED(sys_call_table);
	syscall_table = CB_RESOLVED(sys_call_table);

	restore_hooks(syscall_table, enableHooks);

	// Handle special cases for 32-bit system calls.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	{
		p_sys_call_table syscall_table_i32;
		TRY_CB_RESOLVED(ia32_sys_call_table);
		syscall_table_i32 = CB_RESOLVED(ia32_sys_call_table);

		restore_32bit_hooks(syscall_table_i32, enableHooks);
	}
#endif

CATCH_DEFAULT:
	cb_destroyspinlock(&page_rw_lock);
}

#ifdef HOOK_SELECTOR
static void setSyscall(const char *buf, const char *name, uint32_t syscall,
		       int nr, void *cb_call, void *krn_call, void **table)
{
	int cpu;
	void *call = NULL;
	if (0 == strncmp("1", buf, sizeof(char))) {
		PR_DEBUG("Adding %s", name);
		g_enableHooks |= syscall;
		call = cb_call;
	} else if (0 == strncmp("0", buf, sizeof(char))) {
		PR_DEBUG("Removing %s", name);
		g_enableHooks &= ~syscall;
		call = krn_call;
	} else {
		PRINTK(KERN_WARNING, "Error adding %s to %s", buf, name);
		return;
	}

	// Disable CPU write protect, and restore the call table
	cpu = get_cpu();
	GPF_DISABLE;
	if (set_page_state_rw(table)) {
		table[nr] = call;
		restore_page_state(table);
	}
	GPF_ENABLE;
	put_cpu();
}

static int getSyscall(uint32_t syscall, struct seq_file *m)
{
	seq_printf(m, (g_enableHooks & syscall ? "1\n" : "0\n"));
	return 0;
}

int cb_syscall_clone_get(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_clone, m);
}
int cb_syscall_fork_get(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_fork, m);
}
int cb_syscall_vfork_get(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_vfork, m);
}
int cb_syscall_recvfrom_get(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_recvfrom, m);
}
int cb_syscall_recvmsg_get(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_recvmsg, m);
}
int cb_syscall_recvmmsg_get(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_recvmmsg, m);
}
int cb_syscall_write_get(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_write, m);
}
int cb_syscall_delete_module(struct seq_file *m, void *v)
{
	return getSyscall(CB__NR_delete_module, m);
}

ssize_t cb_syscall_clone_set(struct file *file, const char *buf, size_t size,
			     loff_t *ppos)
{
	setSyscall(buf, "clone", CB__NR_clone, __NR_clone,
		   CBSYSSTUB_NAME(clone), ORIG_SYSCALL_PTR(clone),
		   CB_RESOLVED(sys_call_table));
	return size;
}

ssize_t cb_syscall_fork_set(struct file *file, const char *buf, size_t size,
			    loff_t *ppos)
{
	setSyscall(buf, "fork", CB__NR_fork, __NR_fork, CBSYSSTUB_NAME(fork),
		   ORIG_SYSCALL_PTR(fork), CB_RESOLVED(sys_call_table));
	return size;
}

ssize_t cb_syscall_vfork_set(struct file *file, const char *buf, size_t size,
			     loff_t *ppos)
{
	setSyscall(buf, "vfork", CB__NR_vfork, __NR_vfork,
		   CBSYSSTUB_NAME(vfork), ORIG_SYSCALL_PTR(vfork),
		   CB_RESOLVED(sys_call_table));
	return size;
}

ssize_t cb_syscall_recvfrom_set(struct file *file, const char *buf, size_t size,
				loff_t *ppos)
{
	setSyscall(buf, "recvfrom", CB__NR_recvfrom, __NR_recvfrom,
		   cb_sys_recvfrom, cb_orig_sys_recvfrom,
		   CB_RESOLVED(sys_call_table));
	return size;
}

ssize_t cb_syscall_recvmsg_set(struct file *file, const char *buf, size_t size,
			       loff_t *ppos)
{
	setSyscall(buf, "recvmsg", CB__NR_recvmsg, __NR_recvmsg, cb_sys_recvmsg,
		   cb_orig_sys_recvmsg, CB_RESOLVED(sys_call_table));
	return size;
}

ssize_t cb_syscall_recvmmsg_set(struct file *file, const char *buf, size_t size,
				loff_t *ppos)
{
	setSyscall(buf, "recvmmsg", CB__NR_recvmmsg, __NR_recvmmsg,
		   cb_sys_recvmmsg, cb_orig_sys_recvmmsg,
		   CB_RESOLVED(sys_call_table));
	return size;
}

ssize_t cb_syscall_write_set(struct file *file, const char *buf, size_t size,
			     loff_t *ppos)
{
	setSyscall(buf, "write", CB__NR_write, __NR_write, cb_sys_write,
		   cb_orig_sys_write, CB_RESOLVED(sys_call_table));
	// setSyscall( buf, "write", CB__NR_write,   __NR_ia32_write,
	// cb_sys_write,            cb_orig_sys_write,
	// CB_RESOLVED(ia32_sys_call_table) );
	return size;
}

ssize_t cb_syscall_delete_module(struct file *file, const char *buf,
				 size_t size, loff_t *ppos)
{
	setSyscall(buf, "delete_module", CB__NR_delete_module,
		   __NR_delete_module, cb_sys_delete_module,
		   cb_orig_sys_delete_module, CB_RESOLVED(sys_call_table));
	return size;
}
#endif
