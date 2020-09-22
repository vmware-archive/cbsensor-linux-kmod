/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_HOOK | DS_MOD)
#include "priv.h"
#include "process-tracking.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int on_file_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		 unsigned long flags)
#else
int on_file_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		 unsigned long flags, unsigned long addr,
		 unsigned long addr_only)
#endif
{
	int xcode;
	struct inode *inode;
	struct CB_EVENT *event;
	char *pathname;
	uint64_t pathsz;
	pid_t pid = getpid(current);
	pid_t tid = gettid(current);
	bool path_found;
	MODULE_GET();

	if (((prot & PROT_EXEC) == 0) || (prot & PROT_WRITE)) {
		PR_DEBUG_RATELIMITED("file is (!PROT_EXEC || PROT_WRITE)");
		goto mmap_exit;
	}

	// Occurs during exec to load executable file into memory
	if ((flags & (MAP_DENYWRITE | MAP_EXECUTABLE)) ==
	    (MAP_DENYWRITE | MAP_EXECUTABLE)) {
		PR_DEBUG("mmap for exec");
		goto mmap_exit;
	}

	if (file == NULL) {
		PR_DEBUG("file is NULL");
		goto mmap_exit;
	}

	// Skip if deleted
	if (d_unlinked(file->f_path.dentry)) {
		PR_DEBUG("file is deleted");
		goto mmap_exit;
	}

	if (cbIngoreProcess(pid)) {
		PR_DEBUG("process is ignored");
		goto mmap_exit;
	}

	inode = get_inode_from_file(file);
	if (inode == NULL) {
		PR_DEBUG("inode is NULL");
		goto mmap_exit;
	}

	// Skip if not interesting
	if (!is_interesting_file(inode->i_mode)) {
		PR_DEBUG("inode %ld is not interesting", inode->i_ino);
		goto mmap_exit;
	}

	if (tid != INITTASK) {
		if (cbKillBannedProcessByInode((uint64_t)inode->i_ino)) {
			// do the kill here
		}
	}

	//
	// This is a valid file, allocate an event
	//
	event = logger_alloc_event(CB_EVENT_TYPE_MODULE_LOAD, current);
	if (!event) {
		goto mmap_exit;
	}

	//
	// @@TODO Populate the event cleanup
	//

	// file_get_path() uses dpath which builds the path efficiently
	// by walking back to the root. It starts with a string terminator
	// in the last byte of the target buffer and needs to be copied
	// with memmove to adjust
	path_found =
		file_get_path(file, event->moduleLoad.moduleName, &pathname);
	if (!path_found) {
		PR_DEBUG("mmap failed to get path for pid=%d (%s)", pid,
			 pathname);
		logger_free_event_on_error(event);
		goto mmap_exit;
	}

	pathsz = (&event->moduleLoad.moduleName[PATH_MAX] - pathname);
	if (isSpecialFile(pathname, pathsz)) {
		logger_free_event_on_error(event);
		goto mmap_exit;
	}

	memmove(event->moduleLoad.moduleName, pathname, pathsz);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	event->moduleLoad.baseaddress = 0;
#else
	event->moduleLoad.baseaddress = addr;
#endif
	PR_DEBUG(
		"mmap+ path:%s addr=%llx reqprot=%lx prot=%lux flag=%lux, file:%p",
		event->moduleLoad.moduleName, event->moduleLoad.baseaddress,
		reqprot, prot, flags, file);
	if (!is_process_tracked(pid)) {
		PR_DEBUG("MODLOAD pid=%d not tracked", pid);
		create_process_start_event(current);
	}

	//
	// Queue it to be sent to usermode
	//
	logger_submit_event(event);

mmap_exit:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	xcode = g_original_ops_ptr->mmap_file(file, reqprot, prot, flags);
#else
	xcode = g_original_ops_ptr->file_mmap(file, reqprot, prot, flags, addr,
					      addr_only);
#endif
	MODULE_PUT();
	return xcode;
}
