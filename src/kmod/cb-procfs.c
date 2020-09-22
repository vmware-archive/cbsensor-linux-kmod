/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define DS_MYSUBSYS (DS_PROCFS)
#include "hash-table-generic.h"
#include "priv.h"

typedef int (*fp_readCallback)(struct seq_file *m, void *v);
typedef ssize_t (*fp_writeCallback)(struct file *, const char __user *, size_t,
				    loff_t *);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define PDE_DATA(a) container_of((a), struct proc_inode, vfs_inode)->pde->data
#endif

// Common
struct CbProcFs {
	const char *name;
	fp_readCallback r_callback;
	fp_writeCallback w_callback;
};

static int procfs_read_debug_subsystems(struct seq_file *buffer, void *v)
{
	return seq_printf(buffer, "%x\n", g_debug_subsystem);
}

static ssize_t procfs_write_debug_subsystems(struct file *file,
					     const char __user *buffer,
					     size_t size, loff_t *ppos)
{
	sscanf(buffer, "%x", &g_debug_subsystem);

	// Issue print statements to show which logging levels and subsystems
	// are enabled if DS_TEST is specified.
	if (g_debug_subsystem | DS_TEST) {
		test_logging();
	}

	return size;
}

static const struct CbProcFs proc_callbacks[] = {
	{ "cache", hashtbl_show_proc_cache, NULL },
	{ "debug-subsystems", procfs_read_debug_subsystems,
	  procfs_write_debug_subsystems },
	{ "events-avg", cb_proc_show_events_avg, NULL },
	{ "events-detail", cb_proc_show_events_det, NULL },
	{ "events-reset", NULL, cb_proc_show_events_rst },
	{ "net-track-old", cb_net_track_show_old, NULL },
	{ "net-track-new", cb_net_track_show_new, NULL },
	{ "net-track-purge-age", NULL, cb_net_track_purge_age },
	{ "net-track-purge-all", NULL, cb_net_track_purge_all },
	{ "proc-track-table", cb_proc_track_show_table, NULL },
	{ "proc-track-stats", cb_proc_track_show_stats, NULL },
	{ "file-track-table", cb_file_track_show_table, NULL },
	{ "mem", cb_proc_current_memory_avg, NULL },
	{ "mem-detail", cb_proc_current_memory_det, NULL },

#ifdef HOOK_SELECTOR
	{ "syscall-clone", cb_syscall_clone_get, cb_syscall_clone_set },
	{ "syscall-fork", cb_syscall_fork_get, cb_syscall_fork_set },
	{ "syscall-vfork", cb_syscall_vfork_get, cb_syscall_vfork_set },
	{ "syscall-recvfrom", cb_syscall_recvfrom_get,
	  cb_syscall_recvfrom_set },
	{ "syscall-recvmsg", cb_syscall_recvmsg_get, cb_syscall_recvmsg_set },
	{ "syscall-recvmmsg", cb_syscall_recvmmsg_get,
	  cb_syscall_recvmmsg_set },
	{ "syscall-write", cb_syscall_write_get, cb_syscall_write_set },
	{ "syscall-delete-module", cb_syscall_delete_module,
	  cb_syscall_delete_module },
	{ "netfilter-out", cb_netfilter_local_out_get,
	  cb_netfilter_local_out_set },
	{ "lsm-bprm_check_security", cb_lsm_bprm_check_security_get,
	  cb_lsm_bprm_check_security_set },
	{ "lsm-bprm_committed_creds", cb_lsm_bprm_committed_creds_get,
	  cb_lsm_bprm_committed_creds_set },
	{ "lsm-task_wait", cb_lsm_task_wait_get, cb_lsm_task_wait_set },
	{ "lsm-inode_create", cb_lsm_inode_create_get,
	  cb_lsm_inode_create_set },
	{ "lsm-inode_rename", cb_lsm_inode_rename_get,
	  cb_lsm_inode_rename_set },
	{ "lsm-inode_unlink", cb_lsm_inode_unlink_get,
	  cb_lsm_inode_unlink_set },
	{ "lsm-file_permission", cb_lsm_file_permission_get,
	  cb_lsm_file_permission_set },
	{ "lsm-file_free_security", cb_lsm_file_free_security_get,
	  cb_lsm_file_free_security_set },
	{ "lsm-socket_connect", cb_lsm_socket_connect_get,
	  cb_lsm_socket_connect_set },
	{ "lsm-inet_conn_request", cb_lsm_inet_conn_request_get,
	  cb_lsm_inet_conn_request_set },
	{ "lsm-socket_sock_rcv_skb", cb_lsm_socket_sock_rcv_skb_get,
	  cb_lsm_socket_sock_rcv_skb_set },
	{ "lsm-socket_post_create", cb_lsm_socket_post_create_get,
	  cb_lsm_socket_post_create_set },
	{ "lsm-socket_sendmsg", cb_lsm_socket_sendmsg_get,
	  cb_lsm_socket_sendmsg_set },
	{ "lsm-socket_recvmsg", cb_lsm_socket_recvmsg_get,
	  cb_lsm_socket_recvmsg_set },

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	{ "lsm-mmap_file", cb_lsm_mmap_file_get, cb_lsm_mmap_file_set },
#else
	{ "lsm-file_mmap", cb_lsm_file_mmap_get, cb_lsm_file_mmap_set },
#endif
#endif
	{ 0 }
};

static int dummy_show(struct seq_file *m, void *v)
{
	return 0;
}

static int cb_proc_open(struct inode *inode, struct file *file)
{
	uint64_t procId = (uint64_t)PDE_DATA(inode);
	fp_readCallback callback = proc_callbacks[procId].r_callback;

	if (procId >= (sizeof(proc_callbacks) / sizeof(struct CbProcFs)))
		return -EINVAL;

	return single_open(file, (callback ? callback : dummy_show),
			   PDE_DATA(inode));
}

static ssize_t cb_proc_write(struct file *file, const char __user *buf,
			     size_t size, loff_t *ppos)
{
	uint64_t procId =
		(uint64_t)((struct seq_file *)file->private_data)->private;
	ssize_t len = 0;
	char buffer[20] = { 0 };

	size = (size < 20 ? size : 19);
	if (copy_from_user(buffer, buf, size))
		size = 0;
	buffer[size] = 0;

	if (proc_callbacks[procId].w_callback) {
		len = proc_callbacks[procId].w_callback(file, buffer, size,
							ppos);
	}

	return len;
}

static const struct file_operations cb_fops = {
	.owner = THIS_MODULE,
	.open = cb_proc_open,
	.read = seq_read,
	.write = cb_proc_write,
	.release = single_release,
};

static struct proc_dir_entry *cb_proc_dir;

bool cb_proc_initialize(void)
{
	uint64_t i;

	cb_proc_dir = proc_mkdir("cb", NULL);
	TRY(cb_proc_dir);

	for (i = 0; proc_callbacks[i].name != NULL; ++i) {
		int mode = (proc_callbacks[i].r_callback ? 0400 : 0) |
			   (proc_callbacks[i].w_callback ? 0200 : 0);
		proc_create_data(proc_callbacks[i].name, mode, cb_proc_dir,
				 &cb_fops, (void *)i);
	}
	return true;

CATCH_DEFAULT:
	PRINTK(KERN_ERR, "failed to initialize proc stats");
	return false;
}

void cb_proc_shutdown(void)
{
	int i;

	for (i = 0; proc_callbacks[i].name != NULL; ++i) {
		remove_proc_entry(proc_callbacks[i].name, cb_proc_dir);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	proc_remove(cb_proc_dir);
#else
	remove_proc_entry("cb", NULL);
#endif
}
