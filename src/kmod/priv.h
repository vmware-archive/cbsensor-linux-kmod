/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

// Linux Kernel/LKM headers: module.h is needed by all modules and kernel.h is
// needed for KERN_INFO.
#include <linux/init.h> // included for __init and __exit macros
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/module.h> // included for all kernel modules

#include <linux/connector.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mman.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <net/ipv6.h>

#include "../cbevent/src/CB_EVENT.h"
#include "cb-test.h"
#include "dbg.h"

extern const char DRIVER_NAME[];

#define INITTASK 1 // used by protection software to prevent catastrophic issues

#define CB_SENSOR_MAX_PIDS 5
#define CB_SENSOR_MAX_UIDS 5

extern uint32_t g_eventFilter;
extern uid_t g_cb_server_uid;
extern int64_t g_cb_ignored_pid_count;
extern int64_t g_cb_ignored_uid_count;
extern pid_t g_cb_ignored_pids[CB_SENSOR_MAX_PIDS];
extern uid_t g_cb_ignored_uids[CB_SENSOR_MAX_UIDS];
extern bool g_exiting;

extern bool cbBanningInitialize(void);
extern void cbBanningShutdown(void);
extern bool cbSetBannedProcessInode(uint64_t ino);
extern bool cbClearBannedProcessInode(uint64_t ino);
extern bool cbKillBannedProcessByInode(uint64_t ino);

//-------------------------------------------------
// Module usage protection
//  NOTE: Be very careful when adding new exit points to the hooks that the PUT
//  is properly called
//
extern atomic64_t module_used;
#define MODULE_GET() atomic64_inc_return(&module_used)
#define MODULE_PUT() atomic64_dec_return(&module_used)

//-------------------------------------------------
// Exclusion functions
//
extern void cbSetIgnoredProcess(pid_t pid);
extern void cbClearIgnoredProcess(pid_t pid);
extern bool cbIngoreProcess(pid_t pid);
extern void cbSetIgnoredUid(uid_t uid);
extern bool cbIngoreUid(pid_t uid);

//-------------------------------------------------
// Linux utility functions for locking
//
void cb_initspinlock(uint64_t *sp);
void cb_destroyspinlock(const uint64_t *sp);
void cb_spinunlock(const uint64_t *sp);
void cb_spinlock(const uint64_t *sp);

static inline void *__cb_cache_alloc(struct kmem_cache *cache, gfp_t gfp)
{
	void *dest = kmem_cache_alloc(cache, gfp);
	if (dest) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		memset(dest, 0, cache->object_size);
#else
		memset(dest, 0, cache->buffer_size);
#endif
	}
	return dest;
}

//-------------------------------------------------
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) && RHEL_MINOR <= 3
// CB-10446
// We observed a kernel panic in kmem_cache_alloc affecting only Centos/RHEL 7.
// This was
//  found to be a documented "use after free" issue in the 3.10 kernel which is
//  fixed in 3.10.0-327.22.2.el7.  It appears that using GFP_ATOMIC for ALL
//  kmem_cache_alloc calls seems to workaround the problem. Unfortunately there
//  is no test to differentiate good and bad 3.10 kernels.
//
// http://lkml.iu.edu/hypermail/linux/kernel/1403.1/04340.html
// https://patchwork.ozlabs.org/patch/303498/
#define cb_kmem_cache_alloc(cache, gfp) __cb_cache_alloc(cache, GFP_ATOMIC)
#else
#define cb_kmem_cache_alloc(cache, gfp) __cb_cache_alloc(cache, gfp)
#endif

#define CB__NR_clone 0x00000001
#define CB__NR_fork 0x00000002
#define CB__NR_vfork 0x00000004
#define CB__NR_recvfrom 0x00000008
#define CB__NR_recvmsg 0x00000010
#define CB__NR_recvmmsg 0x00000020
#define CB__NR_write 0x00000040
#define CB__NR_delete_module 0x00000080

#define CB__NF_local_out 0x00000100

#define CB__LSM_bprm_check_security 0x00010000
#define CB__LSM_bprm_committed_creds 0x00020000
#define CB__LSM_task_wait 0x00040000
#define CB__LSM_mmap_file 0x00080000
#define CB__LSM_file_mmap 0x00080000
#define CB__LSM_inode_create 0x00100000
#define CB__LSM_inode_rename 0x00200000
#define CB__LSM_inode_unlink 0x00400000
#define CB__LSM_file_permission 0x00800000
#define CB__LSM_file_free_security 0x01000000
#define CB__LSM_socket_connect 0x02000000
#define CB__LSM_inet_conn_request 0x04000000
#define CB__LSM_socket_sock_rcv_skb 0x08000000
#define CB__LSM_socket_post_create 0x10000000
#define CB__LSM_socket_sendmsg 0x20000000
#define CB__LSM_socket_recvmsg 0x40000000

// ------------------------------------------------
// Module Helpers
//
void cbsensor_shutdown(void);

// ------------------------------------------------
// Linux Security Module Helpers
//
extern bool lsm_initialize(uint32_t enableHooks);
extern void lsm_shutdown(void);
extern bool lsm_hooks_changed(uint32_t enableHooks);

// ------------------------------------------------
// Linux Syscall Hook Helpers
//
#define GPF_DISABLE write_cr0(read_cr0() & (~0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

extern bool syscall_initialize(uint32_t enableHooks);
extern void syscall_shutdown(uint32_t enableHooks);
extern bool syscall_hooks_changed(uint32_t enableHooks);

extern struct security_operations *g_original_ops_ptr;

// ------------------------------------------------
// Netfilter Module Helpers
//
extern bool netfilter_initialize(uint32_t enableHooks);
extern void netfilter_cleanup(uint32_t enableHooks);

// ------------------------------------------------
// Stats Proc Helper
bool cb_proc_initialize(void);
void cb_proc_shutdown(void);
int cb_proc_track_show_table(struct seq_file *m, void *v);
int cb_proc_track_show_stats(struct seq_file *m, void *v);
int cb_file_track_show_table(struct seq_file *m, void *v);

int cb_proc_current_memory_avg(struct seq_file *m, void *v);
int cb_proc_current_memory_det(struct seq_file *m, void *v);

extern pid_t getpid(struct task_struct *task);
extern pid_t gettid(struct task_struct *task);
extern pid_t getppid(struct task_struct *task);
extern struct task_struct *cb_find_task(pid_t pid);
extern void get_starttime(struct timespec *start_time);
extern void create_process_start_event(struct task_struct *task);

// ------------------------------------------------
// Logging
//
extern bool logger_initialize(void);
extern void logger_shutdown(void);

extern struct CB_EVENT *logger_alloc_event(enum CB_EVENT_TYPE eventType,
					   struct task_struct *task);
extern struct CB_EVENT *logger_alloc_event_atomic(enum CB_EVENT_TYPE eventType,
						  struct task_struct *task);
extern struct CB_EVENT *logger_alloc_event_notask(enum CB_EVENT_TYPE eventType,
						  pid_t pid, gfp_t allocType);
extern void logger_free_event_on_error(struct CB_EVENT *event);

extern void logger_submit_event(struct CB_EVENT *event);

extern void logger_submit_event_atomic(struct CB_EVENT *event);

extern bool should_log(enum CB_EVENT_TYPE eventType);

// ------------------------------------------------
// File Operations
//
extern bool user_devnode_init(void);
extern void user_devnode_close(void);

// ------------------------------------------------
// Network Helpers
//
extern size_t cb_ntop(const struct sockaddr *sap, char *buf, size_t buflen,
		      uint16_t *port);

// ------------------------------------------------
// General Helpers
//
uint64_t to_windows_timestamp(struct timespec *tv);

// ------------------------------------------------
// Event Cache
struct CB_EVENT_DATA {
	struct kmem_cache *cb_event_cache;
	atomic64_t eventAllocs;
};

extern struct CB_EVENT_DATA cb_event_data;

extern int cb_proc_show_events_avg(struct seq_file *m, void *v);
extern int cb_proc_show_events_det(struct seq_file *m, void *v);
extern ssize_t cb_proc_show_events_rst(struct file *file, const char *buf,
				       size_t size, loff_t *ppos);
extern ssize_t cb_net_track_purge_age(struct file *file, const char *buf,
				      size_t size, loff_t *ppos);
extern ssize_t cb_net_track_purge_all(struct file *file, const char *buf,
				      size_t size, loff_t *ppos);
extern int cb_net_track_show_new(struct seq_file *m, void *v);
extern int cb_net_track_show_old(struct seq_file *m, void *v);

extern int cb_syscall_clone_get(struct seq_file *m, void *v);
extern ssize_t cb_syscall_clone_set(struct file *file, const char *buf,
				    size_t size, loff_t *ppos);
extern int cb_syscall_fork_get(struct seq_file *m, void *v);
extern ssize_t cb_syscall_fork_set(struct file *file, const char *buf,
				   size_t size, loff_t *ppos);
extern int cb_syscall_vfork_get(struct seq_file *m, void *v);
extern ssize_t cb_syscall_vfork_set(struct file *file, const char *buf,
				    size_t size, loff_t *ppos);
extern int cb_syscall_recvfrom_get(struct seq_file *m, void *v);
extern ssize_t cb_syscall_recvfrom_set(struct file *file, const char *buf,
				       size_t size, loff_t *ppos);
extern int cb_syscall_recvmsg_get(struct seq_file *m, void *v);
extern ssize_t cb_syscall_recvmsg_set(struct file *file, const char *buf,
				      size_t size, loff_t *ppos);
extern int cb_syscall_recvmmsg_get(struct seq_file *m, void *v);
extern ssize_t cb_syscall_recvmmsg_set(struct file *file, const char *buf,
				       size_t size, loff_t *ppos);
extern int cb_syscall_write_get(struct seq_file *m, void *v);
extern ssize_t cb_syscall_write_set(struct file *file, const char *buf,
				    size_t size, loff_t *ppos);

extern int cb_netfilter_local_out_get(struct seq_file *m, void *v);
extern ssize_t cb_netfilter_local_out_set(struct file *file, const char *buf,
					  size_t size, loff_t *ppos);

int cb_lsm_bprm_check_security_get(struct seq_file *m, void *v);
int cb_lsm_bprm_committed_creds_get(struct seq_file *m, void *v);
int cb_lsm_task_wait_get(struct seq_file *m, void *v);
int cb_lsm_inode_create_get(struct seq_file *m, void *v);
int cb_lsm_inode_rename_get(struct seq_file *m, void *v);
int cb_lsm_inode_unlink_get(struct seq_file *m, void *v);
int cb_lsm_file_permission_get(struct seq_file *m, void *v);
int cb_lsm_file_free_security_get(struct seq_file *m, void *v);
int cb_lsm_socket_connect_get(struct seq_file *m, void *v);
int cb_lsm_inet_conn_request_get(struct seq_file *m, void *v);
int cb_lsm_socket_sock_rcv_skb_get(struct seq_file *m, void *v);
int cb_lsm_socket_post_create_get(struct seq_file *m, void *v);
int cb_lsm_socket_sendmsg_get(struct seq_file *m, void *v);
int cb_lsm_socket_recvmsg_get(struct seq_file *m, void *v);

ssize_t cb_lsm_bprm_check_security_set(struct file *file, const char *buf,
				       size_t size, loff_t *ppos);
ssize_t cb_lsm_bprm_committed_creds_set(struct file *file, const char *buf,
					size_t size, loff_t *ppos);
ssize_t cb_lsm_task_wait_set(struct file *file, const char *buf, size_t size,
			     loff_t *ppos);
ssize_t cb_lsm_inode_create_set(struct file *file, const char *buf, size_t size,
				loff_t *ppos);
ssize_t cb_lsm_inode_rename_set(struct file *file, const char *buf, size_t size,
				loff_t *ppos);
ssize_t cb_lsm_inode_unlink_set(struct file *file, const char *buf, size_t size,
				loff_t *ppos);
ssize_t cb_lsm_file_permission_set(struct file *file, const char *buf,
				   size_t size, loff_t *ppos);
ssize_t cb_lsm_file_free_security_set(struct file *file, const char *buf,
				      size_t size, loff_t *ppos);
ssize_t cb_lsm_socket_connect_set(struct file *file, const char *buf,
				  size_t size, loff_t *ppos);
ssize_t cb_lsm_inet_conn_request_set(struct file *file, const char *buf,
				     size_t size, loff_t *ppos);
ssize_t cb_lsm_socket_sock_rcv_skb_set(struct file *file, const char *buf,
				       size_t size, loff_t *ppos);
ssize_t cb_lsm_socket_post_create_set(struct file *file, const char *buf,
				      size_t size, loff_t *ppos);
ssize_t cb_lsm_socket_sendmsg_set(struct file *file, const char *buf,
				  size_t size, loff_t *ppos);
ssize_t cb_lsm_socket_recvmsg_set(struct file *file, const char *buf,
				  size_t size, loff_t *ppos);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int cb_lsm_mmap_file_get(struct seq_file *m, void *v);
ssize_t cb_lsm_mmap_file_set(struct file *file, const char *buf, size_t size,
			     loff_t *ppos);
#else
int cb_lsm_file_mmap_get(struct seq_file *m, void *v);
ssize_t cb_lsm_file_mmap_set(struct file *file, const char *buf, size_t size,
			     loff_t *ppos);
#endif

// ------------------------------------------------
// File Helpers
//
extern bool file_helper_init(void);
extern bool file_get_path(struct file *file, char *buffer, char **pathname);
extern char *dentry_to_path(struct dentry *dentry, char *buf);
extern struct inode *get_inode_from_file(struct file *file);
extern struct inode *get_inode_from_dentry(struct dentry *dentry);
extern bool is_interesting_file(umode_t mode);
extern int isSpecialFile(char *pathname, int len);

//------------------------------------
// Symbol lookup
//
#define CB_KALLSYMS_BUFFER 2048

#define _C ,

// Global pointer resolution
//  This section defines global symbols (variables or functions) that are not
//  exported to modules. These symbols will be discovered at runtime and can be
//  used in code with the CB_RESOLVED( S_NAME ) macro.

// This macro can be used in code to access a symbol we looked up at runtime. It
// is important to verify symbol is not NULL before use.
// (It will be NULL if the symbol was not found.)
#define CB_RESOLVED(S_NAME) g_resolvedSymbols.S_NAME
#define CB_CHECK_RESOLVED(S_NAME) (g_resolvedSymbols.S_NAME != NULL)
#define TRY_CB_RESOLVED(S_NAME)                      \
	TRY_MSG(CB_CHECK_RESOLVED(S_NAME), KERN_ERR, \
		"Function pointer \"%s\" is NULL.", #S_NAME)

// Define a list of symbols using the CB_RESOLV_VARIABLE(V_TYPE, V_NAME) and
// CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL) macros.
// Note, these macros are special.  They are defined just before
//  CB_RESOLV_SYMBOLS is expanded. This allows us to list a symbol name only
//  once, and it will be used correctly in several places.
#define CB_RESOLV_SYMBOLS                                                    \
	CB_RESOLV_FUNCTION(int, access_process_vm,                           \
			   struct task_struct *tsk _C unsigned long addr     \
				   _C void *buf _C int len _C int write)     \
	CB_RESOLV_FUNCTION(char *, dentry_path,                              \
			   struct dentry *dentry _C char *buf _C int buflen) \
	CB_RESOLV_FUNCTION(bool, current_chrooted, void)                     \
	CB_RESOLV_FUNCTION(pte_t *, lookup_address,                          \
			   unsigned long address _C unsigned int *level)     \
	CB_RESOLV_VARIABLE(void *, sys_call_table)                           \
	CB_RESOLV_VARIABLE(void *, ia32_sys_call_table)                      \
	CB_RESOLV_VARIABLE(struct security_operations *, security_ops)       \
	CB_RESOLV_FUNCTION(struct task_struct *, find_task_by_vpid, pid_t nr)

// Here we declare the typedefs for the symbol pointer we will eventually look
// up.  "p_" will be prepended to the symbol name.
#undef CB_RESOLV_VARIABLE
#undef CB_RESOLV_FUNCTION
#define CB_RESOLV_VARIABLE(V_TYPE, V_NAME) typedef V_TYPE *p_##V_NAME;
#define CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL) \
	typedef F_TYPE (*p_##F_NAME)(ARGS_DECL);
CB_RESOLV_SYMBOLS

// Here we declare CB_RESOLVED_SYMS struct that holds all the symbols we will
// eventually look up.
typedef struct _CB_RESOLVED_SYMS {
#undef CB_RESOLV_FUNCTION
#undef CB_RESOLV_VARIABLE
#define CB_RESOLV_VARIABLE(V_TYPE, V_NAME) p_##V_NAME V_NAME;
#define CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL) \
	CB_RESOLV_VARIABLE(F_TYPE, F_NAME);
	CB_RESOLV_SYMBOLS
} CB_RESOLVED_SYMS;

// Define the actual storage variable
extern CB_RESOLVED_SYMS g_resolvedSymbols;
#define INIT_CB_RESOLVED_SYMS() CB_RESOLVED_SYMS g_resolvedSymbols = { 0 }

// Helpers
struct symbols_s {
	char *name;
	int len;
	unsigned long *addr;
};
struct symbol_list {
	struct symbols_s *symbols;
	unsigned long size;
	unsigned long count;
};
extern void lookup_symbols(struct symbol_list *sym_list);
extern void printAddress(char *msg, const char *fn, const struct sock *sk,
			 const struct sockaddr *localAddr,
			 const struct sockaddr *remoteAddr);
