/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS DS_BAN
#include "priv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/binfmts.h>
#include <linux/cred.h>
#endif
#include <linux/signal.h>

#include "hash-table-generic.h"
#include "process-tracking.h"

struct BL_TBL_KEY {
	uint64_t inode;
};

struct DenylistEntry {
	struct HashTableNode link;
	struct BL_TBL_KEY key;
	uint64_t hash;
	uint64_t inode;
};

#define PROTECTION_DISABLED 0
#define PROTECTION_ENABLED 1
#define CB_BANNING_CACHE_OBJ_SZ 64

struct HashTbl *g_banning_table = NULL;
int64_t g_banned_process_by_inode_count = 0;
uint32_t g_protectionModeEnabled = PROTECTION_ENABLED; // Default to enabled

void cbKillRunningBannedProcessByInode(uint64_t ino);

bool cbBanningInitialize(void)
{
	g_protectionModeEnabled = PROTECTION_ENABLED;
	g_banned_process_by_inode_count = 0;
	g_banning_table = hashtbl_init_generic(
		8192, sizeof(struct DenylistEntry), CB_BANNING_CACHE_OBJ_SZ,
		"cb_banning_cache", sizeof(struct BL_TBL_KEY),
		offsetof(struct DenylistEntry, key),
		offsetof(struct DenylistEntry, link));

	if (!g_banning_table) {
		PRINTK(KERN_ERR, "Failed to initialize banning hash table");
		return false;
	}

	return true;
}

void cbBanningShutdown(void)
{
	if (g_banning_table) {
		hashtbl_shutdown_generic(g_banning_table);
	}
}

void cbSetProtectionState(uint32_t new_state)
{
	uint32_t current_state =
		atomic_read((atomic_t *)&g_protectionModeEnabled);

	if (current_state == new_state) {
		return;
	}

	PRINTK(KERN_INFO, "Setting protection state to %u", new_state);
	atomic_set((atomic_t *)&g_protectionModeEnabled, new_state);
}

bool cbSetBannedProcessInode(uint64_t ino)
{
	struct DenylistEntry *bep;
	bool retval = true;
	int64_t i =
		atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);

	PR_DEBUG("Received ino=%llu inode count=%lld", ino, i);

	bep = (struct DenylistEntry *)hashtbl_alloc_generic(g_banning_table,
							    GFP_KERNEL);
	if (bep == NULL) {
		retval = false;
		goto sbpi_exit;
	}

	bep->key.inode = ino;
	bep->hash = 0;
	bep->inode = ino;

	if (hashtbl_add_generic(g_banning_table, bep) < 0) {
		hashtbl_free_generic(g_banning_table, bep);
		retval = false;
		goto sbpi_exit;
	}
	atomic64_inc((atomic64_t *)&g_banned_process_by_inode_count);

sbpi_exit:

	// Lets see if it has to be killed be for we exit
	cbKillRunningBannedProcessByInode(ino);

	return retval;
}

inline bool cbClearBannedProcessInode(uint64_t ino)
{
	int64_t count =
		atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);
	struct DenylistEntry *bep;
	struct BL_TBL_KEY key = { ino };

	if (count == 0 || ino == 0) {
		return false;
	}

	bep = (struct DenylistEntry *)hashtbl_del_by_key_generic(
		g_banning_table, &key);
	if (!bep) {
		return false;
	}
	PR_DEBUG("Clearing banned inode ino=%llu count=%lld", ino, count);

	hashtbl_free_generic(g_banning_table, bep);
	atomic64_dec((atomic64_t *)&g_banned_process_by_inode_count);
	return true;
}

void cbClearAllBans(void)
{
	int64_t count =
		atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);

	if (count == 0) {
		return;
	}

	PR_DEBUG("Clearing all bans");
	atomic64_set((atomic64_t *)&g_banned_process_by_inode_count, 0);
	hashtbl_clear_generic(g_banning_table);
}

bool cbKillBannedProcessByInode(uint64_t ino)
{
	int64_t count;
	struct DenylistEntry *bep;
	struct BL_TBL_KEY key = { ino };

	if (atomic_read((atomic_t *)&g_protectionModeEnabled) ==
	    PROTECTION_DISABLED) {
		PR_DEBUG("protection is disabled");
		goto kbpbi_exit;
	}

	count = atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);
	PR_DEBUG("Check for banned inode=%llu count=%lld", ino, count);
	if (count == 0 || ino == 0) {
		goto kbpbi_exit;
	}

	bep = (struct DenylistEntry *)hashtbl_get_generic(g_banning_table,
							  &key);
	if (!bep) {
		PR_DEBUG("kill banned process failed to find ino=%llu", ino);
		goto kbpbi_exit;
	}

	if (ino == bep->inode) {
		PR_DEBUG("Banned inode=%llu", ino);
		return true;
	}

kbpbi_exit:
	return false;
}

void cbKillRunningBannedProcessByInode(uint64_t ino)
{
	pid_t pid;
	struct siginfo info;
	int ret;
	struct list_head *pos, *safe_del;
	struct ProcessTracking *procp = NULL;
	struct CB_EVENT *event;
	struct RunningBannedInodeInfo sRunningInodesToBan;
	struct processes_to_ban *temp = NULL;

	if (atomic_read((atomic_t *)&g_protectionModeEnabled) ==
	    PROTECTION_DISABLED) {
		PR_DEBUG("protection is disabled");
		return;
	}

	PRINTK(KERN_INFO, "Kill process with ino=%llu", ino);

	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIGKILL;
	info.si_code = 0;
	info.si_errno = 1234;

	memset(&sRunningInodesToBan, 0, sizeof(struct RunningBannedInodeInfo));
	sRunningInodesToBan.inode = ino;
	sRunningInodesToBan.count = 0;
	INIT_LIST_HEAD(&sRunningInodesToBan.BanList.list);

	is_process_tracked_get_state_by_inode(&sRunningInodesToBan);

	if (!sRunningInodesToBan.count) {
		PR_DEBUG("failed to find process with ino=%llu", ino);
		return;
	}

	list_for_each (pos, &sRunningInodesToBan.BanList.list) {
		procp = (struct ProcessTracking
				 *)(list_entry(pos, struct processes_to_ban,
					       list)
					    ->procp);
		pid = procp->pt_key.pid;

		//
		// allocate an event
		//
		event = logger_alloc_event_atomic(CB_EVENT_TYPE_PROCESS_BLOCKED,
						  NULL);
		if (event) {
			//
			// Populate the event
			//
			event->procInfo.pid = procp->pt_key.pid;

			event->blockResponse.blockType =
				ProcessTerminatedAfterStartup;
			event->blockResponse.uid = procp->uid;
			event->blockResponse.inode = ino;

			strncpy(event->blockResponse.path, procp->taskp->comm,
				sizeof(procp->taskp->comm));
			event->blockResponse.path[sizeof(procp->taskp->comm)] =
				0;
			PR_DEBUG("cb kill %s %d %llu %d",
				 event->blockResponse.path, pid, ino,
				 event->blockResponse.blockType);
		}

		ret = send_sig_info(SIGKILL, &info, procp->taskp);
		if (!ret) {
			PRINTK(KERN_INFO, "killed process with ino=%llu pid=%d",
			       ino, pid);
			if (event) {
				logger_submit_event(event);
			}
			continue;
		}

		if (event) {
			logger_free_event_on_error(event);
		}
		PRINTK(KERN_WARNING,
		       "error sending kill to process with ino=%llu pid=%d",
		       ino, pid);
	}

	// Clean up the list
	list_for_each_safe (pos, safe_del, &sRunningInodesToBan.BanList.list) {
		temp = list_entry(pos, struct processes_to_ban, list);
		list_del(pos);
		kfree(temp);
	}

	memset(&sRunningInodesToBan, 0, sizeof(struct RunningBannedInodeInfo));
}

bool cbIngoreProcess(pid_t pid)
{
	int64_t i;
	int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_pid_count);

	PR_DEBUG_RATELIMITED("Test if pid=%u should be ignored count=%lld", pid,
			     max);

	if (max == 0) {
		goto ignore_process_exit;
	}

	for (i = 0; i < max; ++i) {
		if (g_cb_ignored_pids[i] == pid) {
			PR_DEBUG("Ignore pid=%u", pid);
			return true;
		}
	}

ignore_process_exit:
	return false;
}

void cbSetIgnoredProcess(pid_t pid)
{
	int64_t i;
	int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_pid_count);

	// Search for pid
	for (i = 0; i < max; ++i) {
		if (g_cb_ignored_pids[i] == pid) {
			PR_DEBUG("already ignoring pid=%u", pid);
			return;
		}
	}

	if (max < CB_SENSOR_MAX_PIDS) {
		g_cb_ignored_pids[max] = pid;
		max += 1;
		atomic64_set((atomic64_t *)&g_cb_ignored_pid_count, max);
		PRINTK(KERN_INFO, "Adding pid=%u at %lld", pid, max);
	}
}

void cbClearIgnoredProcess(pid_t pid)
{
	int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_pid_count);

	if (max) {
		atomic64_set((atomic64_t *)&g_cb_ignored_pid_count, 0);
		memset(g_cb_ignored_pids, 0, sizeof(g_cb_ignored_pids));
	}
}

bool cbIngoreUid(pid_t uid)
{
	int64_t i;
	int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_uid_count);

	PR_DEBUG_RATELIMITED("Test if uid=%u should be ignored", uid);

	if (max == 0) {
		goto ignore_uid_exit;
	}

	for (i = 0; i < max; ++i) {
		if (g_cb_ignored_uids[i] == uid) {
			PR_DEBUG("Ignore uid=%u", uid);
			return true;
		}
	}

ignore_uid_exit:
	return false;
}

void cbSetIgnoredUid(uid_t uid)
{
	int64_t i;
	int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_uid_count);

	// Search for uid
	for (i = 0; i < max; ++i) {
		if (g_cb_ignored_uids[i] == uid) {
			PR_DEBUG("already ignoring uid=%u", uid);
			return;
		}
	}

	if (max < CB_SENSOR_MAX_UIDS) {
		g_cb_ignored_uids[max] = uid;
		max += 1;
		atomic64_set((atomic64_t *)&g_cb_ignored_uid_count, max);
		PRINTK(KERN_INFO, "Adding uid=%u at %lld", uid, max);
	}
}
