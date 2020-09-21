/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "hash-table-generic.h"
#include <linux/sched.h>

struct pt_table_key {
	pid_t pid;
};

// List struct for use by RUNNING_BANNED_INODE_S
struct processes_to_ban {
	void *procp; // Pointer for the process tracking element to ban
	struct list_head list;
};

struct RunningBannedInodeInfo {
	uint64_t count;
	uint64_t inode;
	struct processes_to_ban BanList;
};

struct ProcessTracking {
	struct HashTableNode pt_link;
	struct pt_table_key pt_key;
	uint64_t inode;
	pid_t tid;
	uid_t uid;
	uid_t euid;
	pid_t parent;
	char path[PATH_MAX + 1];
	bool path_found;
	int action; // How did we start

	bool start_sent;

	uint64_t net_op_cnt;
	uint64_t net_connect;
	uint64_t net_accept;
	uint64_t net_dns;

	uint64_t file_op_cnt;
	uint64_t file_create;
	uint64_t file_delete;
	uint64_t file_open; // First write equals open
	uint64_t file_write;
	uint64_t file_close;
	uint64_t file_map_exec;

	uint64_t process_op_cnt;
	uint64_t process_create;
	uint64_t process_exit;

	struct task_struct *taskp;
};

bool process_tracking_initialize(void);
void process_tracking_shutdown(void);

bool process_tracking_insert_process(pid_t pid, pid_t tid, pid_t parent,
				     uid_t uid, uid_t euid, int action,
				     struct task_struct *taskp,
				     struct CB_EVENT *event, bool start_sent);
bool process_tracking_remove_process(pid_t pid);
bool process_tracking_update_process(pid_t pid, pid_t tid, pid_t parent,
				     uid_t uid, uid_t euid, int action,
				     struct task_struct *taskp,
				     struct CB_EVENT *event,
				     enum CB_EVENT_TYPE event_type,
				     bool start_sent);
bool is_process_tracked(pid_t pid);
struct ProcessTracking *is_process_tracked_get_state(pid_t pid);
void is_process_tracked_get_state_by_inode(
	struct RunningBannedInodeInfo *psRunningInodesToBan);
bool process_tracking_get_process(pid_t pid, struct ProcessTracking **procp);
void process_tracking_update_op_cnts(struct ProcessTracking *procp,
				     enum CB_EVENT_TYPE event_type, int action);
bool process_tracking_should_track_user(void);
