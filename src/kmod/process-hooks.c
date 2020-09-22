/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_HOOK | DS_PROC)
#include "priv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/binfmts.h>
#include <linux/cred.h>
#endif
#include "cb-banning.h"
#include "process-tracking.h"
#include <linux/mm.h>
#include <linux/proc_fs.h>

#include "ktfutce.h"
#include <asm/cacheflush.h>
#include <linux/pagemap.h>

static bool _get_cmdline(struct task_struct *task, unsigned long start_addr,
			 unsigned long end_addr, int args, char *cmdLine,
			 size_t cmdLineSize)
{
	unsigned int cmdLinePos = 0;
	int i;
	size_t len = 0;

	if (!task) {
		return false;
	}
	if (CB_RESOLVED(access_process_vm) == NULL) {
		PRINTK(KERN_ERR, "Function pointer access_process_vm is NULL.");
		return false;
	}

	// Verify the buffer exists
	if (cmdLine == NULL) {
		PRINTK(KERN_WARNING, "couldn't allocate cmdline buffer pid:%d",
		       getpid(task));
		return false;
	}
	len = min(cmdLineSize, (size_t)(end_addr - start_addr));

	// Copy the argument string.
	//  NOTE: A simple memcopy does not work because this technically runs
	//  in a different process context than what is about to exec.  So we
	//  need to page in the memory.
	CB_RESOLVED(access_process_vm)(task, start_addr, &cmdLine[0], len, 0);

	// The args are delimited by '\0', so we walk through the  buffer and
	// replace them with ' '.
	for (i = 0; i <= args; ++i) {
		// Find the end of the string and replace it with ' '.  We will
		// start here on the next pass.
		unsigned int arglen =
			strnlen(&cmdLine[cmdLinePos], MAX_ARG_STRLEN);
		if ((cmdLinePos + arglen) > len) {
			break;
		}
		cmdLinePos += arglen + 1;
		cmdLine[cmdLinePos - 1] = ' ';
	}
	cmdLine[(cmdLinePos > 0) ? cmdLinePos - 1 : 0] = '\0';

	return true;
}

struct dentry *get_dentry_from_mm(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	struct dentry *dentryp = NULL;

	if (!mm) {
		goto dentry_mm_exit;
	}

	// Under some situations, the mmap_sem will be locked for write above us
	// in the stack. Eventually, we should fix that. Since this can be
	// called from inside an interrupt we should to avoid a call to sleep so
	// we'll try once and fail if the lock is held.
	if (0 == down_read_trylock(&mm->mmap_sem)) {
		PR_DEBUG("unable to down semaphore");
		goto dentry_mm_exit;
	}

	vma = mm->mmap;

	while (vma) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		if ((vma->vm_flags & VM_EXEC) && vma->vm_file)
#else
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
#endif
		{
			// If the vma's space contains the code section of the
			// actual process, we have the correct one
			if (vma->vm_start <= mm->start_code &&
			    vma->vm_end >= mm->end_code) {
				break;
			}
			// Otherwise, we're likely looking at a module with
			// executable flags set
			else {
				PR_DEBUG(
					"==========EXECUTABLE MODULE LOADED=========");
				PR_DEBUG("pid:%u (%s)", current->pid,
					 current->comm);
				PR_DEBUG("    vma count:    %d", mm->map_count);
				PR_DEBUG("    code section: 0x%lx -> 0x%lx",
					 mm->start_code, mm->end_code);
				PR_DEBUG("    vma(exeflag): 0x%lx -> 0x%lx",
					 vma->vm_start, vma->vm_end);
				PR_DEBUG(
					"    Invalid dentry reference as this executable section is not part of process code.");
				PR_DEBUG(
					"    Continuing to search vma list...");
				PR_DEBUG(
					"===========================================");
			}
		}
		vma = vma->vm_next;
	}

	if (vma && vma->vm_file) {
		dentryp = vma->vm_file->f_dentry;
	}

	up_read(&mm->mmap_sem);

dentry_mm_exit:
	return dentryp;
}

uint64_t get_ino_from_task(struct task_struct *task)
{
	uint64_t ino = 0;
	struct inode *inodep = NULL;
	struct dentry *dentryp = NULL;

	// TODO: We should be locking the task here, but I do not want to add it
	// right now.
	// task_lock(task);
	dentryp = get_dentry_from_mm(task->mm);
	if (dentryp) {
		inodep = get_inode_from_dentry(dentryp);
		if (inodep) {
			ino = inodep->i_ino;
		}
	}
	return ino;
}

//
// Process exit hook
//

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void cb_task_free(struct task_struct *p)
{
	struct CB_EVENT *event;
	int ret;

	MODULE_GET();
	if (!p) {
		PR_DEBUG("cb_task_free null task_struct");
		goto task_free_exit;
	}

	// With our current fork event hook (see function _cb_post_clone), the
	// process tracking table sometimes saves additional records at the
	// thread level, so the clean up here should also based on the thread
	// id.
	if (!p->pid) {
		PR_DEBUG("cb_task_free pid is 0");
		goto task_free_exit;
	}

	if (cbIngoreProcess(p->pid)) {
		cbClearIgnoredProcess(p->pid);
	}

	ret = process_tracking_remove_process(p->pid);
	if (ret) {
		PR_DEBUG("passed: process_tracking_remove_process: pid %d\n",
			 p->pid);
	} else {
		PR_DEBUG("failed: process_tracking_remove_process: pid %d\n",
			 p->pid);
		goto task_free_exit;
	}

	event = logger_alloc_event_notask(CB_EVENT_TYPE_PROCESS_EXIT, p->pid,
					  GFP_ATOMIC);
	if (event) {
		logger_submit_event(event);
	}

task_free_exit:
	g_original_ops_ptr->task_free(p);
	MODULE_PUT();
}
#else
int task_wait(struct task_struct *p)
{
	struct CB_EVENT *event;
	pid_t pid = getpid(p);
	int ret;
	bool removed_process;

	MODULE_GET();

	if (cbIngoreProcess(pid)) {
		cbClearIgnoredProcess(pid);
	}

	// If not the main thread then we shouldn't care too
	if (!(p->pid == p->tgid || thread_group_leader(p))) {
		PR_DEBUG("Task exit %u:", pid);
		goto task_wait_exit;
	}

	if (!(p->state == TASK_DEAD || p->exit_state == EXIT_DEAD)) {
		goto task_wait_exit;
	}

	removed_process = process_tracking_remove_process(pid);
	if (!removed_process) {
		PR_DEBUG("remove process failed to find pid=%u", pid);
		goto task_wait_exit;
	}

	event = logger_alloc_event_atomic(CB_EVENT_TYPE_PROCESS_EXIT, p);
	if (event) {
		logger_submit_event(event);
	}

task_wait_exit:
	ret = g_original_ops_ptr->task_wait(p);
	MODULE_PUT();
	return ret;
}
#endif

// This does nothing but is required by the hook
long _cb_pre_clone(long id, long flags)
{
	return 0;
}

// We should really just allocate log and tracking data
// and have kthread fill in all the data there.
void _cb_post_clone(long id, long flags, long pid)
{
	struct CB_EVENT *event;
	pid_t ppid = getpid(current); // This function is called in the context
		// of forking process
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	uid_t uid = current_cred()->uid.val;
	uid_t euid = current_cred()->euid.val;
#else
	uid_t uid = current_cred()->uid;
	uid_t euid = current_cred()->euid;
#endif
	MODULE_GET();

	// Make sure we are not a thread
	TRY(!(flags & CLONE_THREAD));

	TRY(!cbIngoreProcess(ppid));

	//
	// This is a valid file, allocate an event
	//
	event = logger_alloc_event_atomic(CB_EVENT_TYPE_PROCESS_START, NULL);
	if (event) {
		struct ProcessTracking *procp;
		int ret;

		//
		// Populate the event
		//
		event->procInfo.pid = pid;
		event->processStart.parent = ppid;
		event->processStart.uid =
			process_tracking_should_track_user() ? uid : (uid_t)-1;
		event->processStart.start_action = CB_PROCESS_START_BY_FORK;
		event->processStart.observed = true;
		event->processStart.path[0] = 0;
		event->processStart.path[PATH_MAX] = 0;
		event->processStart.path_found = false;

		if (process_tracking_get_process(ppid, &procp)) {
			strncpy(event->processStart.path, procp->path,
				PATH_MAX);
			event->processStart.path_found = procp->path_found;
			event->processStart.inode = procp->inode;
		} else {
			// If we failed to find the parent, look up the inode
			event->processStart.inode = get_ino_from_task(current);
		}

		//
		// Queue it to be sent to usermode
		//
		process_tracking_insert_process(pid, pid, ppid, uid, euid,
						CB_PROCESS_START_BY_FORK, NULL,
						event, true);
		ret = ktfutce_add_pid(pid, event, GFP_ATOMIC);
		if (ret < 0) {
			logger_free_event_on_error(event);
			process_tracking_remove_process(pid);
		}
	}

CATCH_DEFAULT:
	MODULE_PUT();
}

int cb_bprm_check_security(struct linux_binprm *bprm)
{
	int ret;
	struct CB_EVENT *event;
	struct task_struct *task = current;
	pid_t pid = getpid(task);
	pid_t tid = gettid(task);
	int stat;
	struct inode *inode;
	uint64_t ino = 0;
	bool killit = false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	uid_t uid = current_cred()->uid.val;
#else
	uid_t uid = current_cred()->uid;
#endif
	char *pathname = NULL;
	MODULE_GET();

	if (cbIngoreProcess(pid)) {
		goto check_security_exit;
	}

	inode = get_inode_from_file(bprm->file);
	if (inode == NULL) {
		goto check_security_exit;
	}

	ino = inode->i_ino;
	PR_DEBUG(
		"set creds check for banned process %s pid=%d uid:%d inode=%llu",
		bprm->filename, pid, uid, ino);

	if (tid != INITTASK) {
		killit = cbKillBannedProcessByInode(ino);
	}

	stat = g_original_ops_ptr->bprm_set_creds(bprm);
	if (stat || killit) {
		PR_DEBUG("set creds kill %s %d %llu %d %d", bprm->filename, pid,
			 ino, killit, stat);

		if (killit) {
			//
			// This is a valid file, allocate an event
			//
			event = logger_alloc_event(
				CB_EVENT_TYPE_PROCESS_BLOCKED, task);
			if (event) {
				//
				// Populate the event
				//
				event->blockResponse.blockType =
					BlockDuringProcessStartup;
				event->blockResponse.uid = uid;
				event->blockResponse.inode = ino;

				// file_get_path() uses dpath which builds the
				// path efficiently by walking back to the root.
				// It starts with a string terminator in the
				// last byte of the target buffer and needs to
				// be copied with memmove to adjust
				event->blockResponse.path_found = file_get_path(
					bprm->file, event->blockResponse.path,
					&pathname);
				_get_cmdline(
					current, bprm->p, bprm->exec,
					bprm->argc,
					event->blockResponse.cmdLine.v,
					sizeof(event->blockResponse.cmdLine.v));
				if (pathname && strlen(pathname) > 0) {
					uint64_t pathsz =
						(&event->blockResponse
							  .path[PATH_MAX] -
						 pathname);
					//
					// Log it
					//
					memmove(event->blockResponse.path,
						pathname, pathsz);
				}

				if (!event->blockResponse.path_found) {
					PR_DEBUG(
						"Failed to retrieve path for pid: %d, filename: %s",
						pid, event->processStart.path);
				}

				PR_DEBUG("cb kill %s %d %llu %d",
					 event->blockResponse.path, pid, ino,
					 event->blockResponse.blockType);
				logger_submit_event(event);
			} else {
				PR_DEBUG(
					"set creds kill failed to allocate event %s %d %llu",
					bprm->filename, pid, ino);
			}
		}
		MODULE_PUT();
		return -EPERM;
	}

check_security_exit:
	ret = g_original_ops_ptr->bprm_check_security(bprm);
	MODULE_PUT();
	return ret;
}

//
// Process start hook.  Callout called late in the exec process
//
void cb_bprm_committed_creds(struct linux_binprm *bprm)
{
	struct CB_EVENT *event;
	struct task_struct *task = current;
	pid_t pid = getpid(task);
	pid_t tid = gettid(task);
	pid_t ppid = getppid(task);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	uid_t uid = current_cred()->uid.val;
	uid_t euid = current_cred()->euid.val;
#else
	uid_t uid = current_cred()->uid;
	uid_t euid = current_cred()->euid;
#endif
	struct inode *inode;
	uint64_t ino = 0;
	char *pathname;
	struct ProcessTracking *procp = NULL;
	MODULE_GET();

	if (cbIngoreProcess(pid)) {
		goto commited_creds_exit;
	}

	inode = get_inode_from_file(bprm->file);
	if (inode) {
		ino = inode->i_ino;
	}

	// Our parent may have died by the time we are called, so get the
	// observed parent pid
	//  from the tracking data.
	procp = is_process_tracked_get_state(pid);
	if (procp) {
		ppid = procp->parent;
	}

	//
	// This is a valid file, allocate an event
	//
	event = logger_alloc_event(CB_EVENT_TYPE_PROCESS_START, task);
	if (!event) {
		goto commited_creds_exit;
	}

	//
	// Populate the event
	//
	event->processStart.parent = ppid;
	event->processStart.uid =
		process_tracking_should_track_user() ? uid : (uid_t)-1;
	event->processStart.inode = ino;
	event->processStart.start_action = CB_PROCESS_START_BY_EXEC;
	event->processStart.observed = true;
	event->processStart.path_found = false;

	// file_get_path() uses dpath which builds the path efficiently
	// by walking back to the root. It starts with a string terminator
	// in the last byte of the target buffer and needs to be copied
	// with memmove to adjust
	event->processStart.path_found =
		file_get_path(bprm->file, event->processStart.path, &pathname);
	if (pathname && strlen(pathname) > 0) {
		uint64_t pathsz =
			(&event->processStart.path[PATH_MAX] - pathname);
		//
		// Log it
		//
		memmove(event->processStart.path, pathname, pathsz);
	}

	if (!event->processStart.path_found) {
		PR_DEBUG("Failed to retrieve path for pid: %d, filename: %s",
			 pid, event->processStart.path);
	}

	_get_cmdline(current, bprm->p, bprm->exec, bprm->argc - 1,
		     event->processStart.cmdLine.v,
		     sizeof(event->processStart.cmdLine.v));

	if (procp) {
		// Update the existing process on exec
		process_tracking_update_process(
			pid, tid, ppid, uid, euid, CB_PROCESS_START_BY_EXEC,
			task, event, CB_EVENT_TYPE_PROCESS_START, true);
		PR_DEBUG("exec tracked pid=%d path=%s inode=%llu", pid,
			 event->processStart.path, ino);
	} else {
		if (!is_process_tracked(ppid)) {
			PR_DEBUG("exec ppid=%d not tracked", ppid);
			create_process_start_event(task->real_parent);
		}
		process_tracking_insert_process(pid, tid, ppid, uid, euid,
						CB_PROCESS_START_BY_EXEC, task,
						event, true);
		PR_DEBUG("exec track pid=%d path=%s inode=%llu", pid,
			 event->processStart.path, ino);
	}

	//
	// Queue it to be sent to usermode
	//
	PR_DEBUG("process exec %s %d by %d uid=%d path=%s inode=%llu",
		 event->processStart.path, pid, ppid, uid,
		 event->processStart.path, ino);

	logger_submit_event(event);

commited_creds_exit:
	g_original_ops_ptr->bprm_committed_creds(bprm);
	MODULE_PUT();
}
