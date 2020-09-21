/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS DS_PROC
#include "priv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/binfmts.h>
#include <linux/cred.h>
#endif
#include "process-tracking.h"

#include "../cbevent/src/CB_EVENT_FILTER.h"

uint64_t g_pt_process_op_cnt = 0;
uint64_t g_pt_process_create = 0;
uint64_t g_pt_process_exit = 0;
uint64_t g_pt_process_create_by_fork = 0;
uint64_t g_pt_process_create_by_exec = 0;

extern uint32_t g_pid_gc_freq;

#define CLEAR_DEAD_JIFFIES msecs_to_jiffies(g_pid_gc_freq * 1000)
static void process_tracking_clear_dead(struct work_struct *work);
static DECLARE_DELAYED_WORK(g_proc_clear_dead_work,
			    process_tracking_clear_dead);
#define CB_PT_CACHE_OBJ_SZ 256

struct HashTbl *g_process_tracking_table = NULL;

struct dentry *get_dentry_from_mm(struct mm_struct *mm);

bool process_tracking_should_track_user()
{
	return (g_eventFilter & CB_EVENT_FILTER_PROCESSUSER) ==
	       CB_EVENT_FILTER_PROCESSUSER;
}

bool process_tracking_initialize(void)
{
	g_process_tracking_table = hashtbl_init_generic(
		8192, sizeof(struct ProcessTracking), CB_PT_CACHE_OBJ_SZ,
		"cb_pt_cache", sizeof(struct pt_table_key),
		offsetof(struct ProcessTracking, pt_key),
		offsetof(struct ProcessTracking, pt_link));
	if (!g_process_tracking_table) {
		PRINTK(KERN_ERR,
		       "failed to initialize process tracking hash table");
		return false;
	}

	if (CLEAR_DEAD_JIFFIES) {
		schedule_delayed_work(&g_proc_clear_dead_work,
				      CLEAR_DEAD_JIFFIES);
	}

	return true;
}

void process_tracking_shutdown(void)
{
	if (g_process_tracking_table) {
		cancel_delayed_work(&g_proc_clear_dead_work);
		hashtbl_shutdown_generic(g_process_tracking_table);
		g_process_tracking_table = NULL;
	}
}

bool process_tracking_insert_process(pid_t pid, pid_t tid, pid_t parent,
				     uid_t uid, uid_t euid, int action,
				     struct task_struct *taskp,
				     struct CB_EVENT *event, bool start_sent)
{
	struct ProcessTracking *procp;

	// Double check to make sure that this process is not already tracked.
	// This *should* not
	//  happen. But in theory we could have missed a process exit somewhere.
	if (process_tracking_remove_process(pid)) {
		PR_DEBUG("Cleaning up duplicate process pid=%d", pid);
	}

	procp = (struct ProcessTracking *)hashtbl_alloc_generic(
		g_process_tracking_table, GFP_ATOMIC);
	if (procp == NULL) {
		return false;
	}

	procp->pt_key.pid = pid;
	procp->tid = tid;
	procp->parent = parent;
	procp->uid = uid;
	procp->euid = euid;
	procp->action = action;
	procp->inode = event->processStart.inode;
	procp->start_sent = start_sent;
	procp->process_op_cnt = 0;
	procp->process_create = 0;
	procp->file_op_cnt = 0;
	procp->file_map_exec = 0;
	procp->file_create = 0;
	procp->file_delete = 0;
	procp->file_open = 0;
	procp->file_write = 0;
	procp->file_close = 0;
	procp->net_op_cnt = 0;
	procp->net_connect = 0;
	procp->net_accept = 0;
	procp->net_dns = 0;
	procp->taskp = taskp;
	procp->path[0] = 0;
	procp->path[PATH_MAX] = 0;

	memcpy(procp->path, event->processStart.path, PATH_MAX);
	procp->path_found = event->processStart.path_found;

	g_pt_process_op_cnt += 1;
	g_pt_process_create += 1;

	if (action == CB_PROCESS_START_BY_FORK) {
		g_pt_process_create_by_fork += 1;
	} else if (action == CB_PROCESS_START_BY_EXEC) {
		g_pt_process_create_by_exec += 1;
	}

	if (hashtbl_add_generic(g_process_tracking_table, procp) < 0) {
		hashtbl_free_generic(g_process_tracking_table, procp);
		return false;
	}

	PR_DEBUG_RATELIMITED("create pid=%d opcnt=%llu create=%llu exit=%llu",
			     pid, g_pt_process_op_cnt, g_pt_process_create,
			     g_pt_process_exit);
	return true;
}

bool process_tracking_remove_process(pid_t pid)
{
	struct ProcessTracking *procp;
	struct pt_table_key key = { pid };

	procp = (struct ProcessTracking *)hashtbl_del_by_key_generic(
		g_process_tracking_table, &key);
	if (!procp) {
		return false;
	}

	hashtbl_free_generic(g_process_tracking_table, procp);

	g_pt_process_op_cnt += 1;
	g_pt_process_exit += 1;
	PR_DEBUG_RATELIMITED("remove pid=%d opcnt=%llu create=%llu exit=%llu",
			     pid, g_pt_process_op_cnt, g_pt_process_create,
			     g_pt_process_exit);
	return true;
}

void process_tracking_update_op_cnts(struct ProcessTracking *procp,
				     enum CB_EVENT_TYPE event_type, int action)
{
	switch (event_type) {
	case CB_EVENT_TYPE_PROCESS_START:
		procp->process_op_cnt += 1;
		procp->process_create += 1;
		if (action == CB_PROCESS_START_BY_FORK) {
			g_pt_process_create_by_fork += 1;
		} else if (action == CB_PROCESS_START_BY_EXEC) {
			g_pt_process_create_by_exec += 1;
		}
		break;

	case CB_EVENT_TYPE_PROCESS_EXIT:
		procp->process_op_cnt += 1;
		procp->process_exit += 1;
		break;

	case CB_EVENT_TYPE_MODULE_LOAD:
		procp->file_op_cnt += 1;
		procp->file_map_exec += 1;
		break;

	case CB_EVENT_TYPE_FILE_CREATE:
		procp->file_op_cnt += 1;
		procp->file_create += 1;
		break;

	case CB_EVENT_TYPE_FILE_DELETE:
		procp->file_op_cnt += 1;
		procp->file_delete += 1;
		break;

	case CB_EVENT_TYPE_FILE_WRITE:
		procp->file_op_cnt += 1;
		if (procp->file_write == 0) {
			procp->file_open += 1;
		}
		procp->file_write += 1;

	case CB_EVENT_TYPE_FILE_CLOSE:
		procp->file_op_cnt += 1;
		procp->file_close += 1;
		break;

	case CB_EVENT_TYPE_NET_CONNECT_PRE:
		procp->net_op_cnt += 1;
		procp->net_connect += 1;
		break;

	case CB_EVENT_TYPE_NET_CONNECT_POST:
		procp->net_op_cnt += 1;
		procp->net_connect += 1;
		break;

	case CB_EVENT_TYPE_NET_ACCEPT:
		procp->net_op_cnt += 1;
		procp->net_accept += 1;
		break;

	case CB_EVENT_TYPE_DNS_RESPONSE:
		procp->net_op_cnt += 1;
		procp->net_dns += 1;
		break;

	default:
		break;
	}
}

bool process_tracking_update_process(pid_t pid, pid_t tid, pid_t parent,
				     uid_t uid, uid_t euid, int action,
				     struct task_struct *taskp,
				     struct CB_EVENT *event,
				     enum CB_EVENT_TYPE event_type,
				     bool start_sent)
{
	struct ProcessTracking *procp;
	struct pt_table_key key = { pid };

	procp = (struct ProcessTracking *)hashtbl_get_generic(
		g_process_tracking_table, &key);
	if (!procp) {
		PR_DEBUG("update process failed to find pid=%d", pid);
		return false;
	}

	if (procp->tid != tid) {
		procp->tid = tid;
	}

	if (procp->parent != parent) {
		procp->parent = parent;
	}

	if (procp->uid != uid) {
		procp->uid = uid;
	}

	if (procp->euid != euid) {
		procp->euid = euid;
	}

	if (procp->action != action) {
		procp->action = action;
	}

	if (procp->inode != event->processStart.inode) {
		procp->inode = event->processStart.inode;
	}

	if (procp->start_sent != start_sent) {
		procp->start_sent = start_sent;
	}

	procp->taskp = taskp;

	// Always update the path
	memcpy(procp->path, event->processStart.path, PATH_MAX);
	procp->path_found = event->processStart.path_found;

	process_tracking_update_op_cnts(procp, event_type, action);

	return true;
}

struct ProcessTracking *is_process_tracked_get_state(pid_t pid)
{
	struct pt_table_key key = { pid };
	return ((struct ProcessTracking *)hashtbl_get_generic(
		g_process_tracking_table, &key));
}

// Note: This function is used as a callback by hashtbl_for_each_generic called
// from is_process_tracked_get_state_by_inode also note that it is called from
// inside a spinlock. Therefore, in the future if modifications are required,
// be aware that any function call that may sleep should be avoided.
// We also allocate an array of pointers and it is the responsibility of the
// caller to free them when done.
static int _hashtbl_search_callback(struct HashTbl *hashTblp,
				    struct HashTableNode *nodep, void *priv)
{
	struct ProcessTracking *procp = NULL;
	struct RunningBannedInodeInfo *psRunningInodesToBan = NULL;
	struct processes_to_ban *temp = NULL;

	// Saftey first
	if (NULL == nodep || NULL == priv) {
		PRINTK(KERN_ERR,
		       "NULL ptr provided as function argument [%p=nodep %p=priv]. Bailing...",
		       nodep, priv);
		goto EXIT;
	}

	procp = (struct ProcessTracking *)nodep;
	psRunningInodesToBan = (struct RunningBannedInodeInfo *)priv;

	// Did we match based on inode?
	if (procp->inode == psRunningInodesToBan->inode) {
		// Allocate a new list element for banning to hold this process
		// pointer
		temp = (struct processes_to_ban *)kmalloc(
			sizeof(struct processes_to_ban), GFP_ATOMIC);
		if (NULL == temp) {
			PRINTK(KERN_ERR, "Out of memory!");
			goto EXIT;
		}

		// Update our structure
		temp->procp = procp;
		list_add(&(temp->list), &(psRunningInodesToBan->BanList.list));
		psRunningInodesToBan->count++;
	}
EXIT:
	return ACTION_CONTINUE;
}

void is_process_tracked_get_state_by_inode(
	struct RunningBannedInodeInfo *psRunningInodesToBan)
{
	hashtbl_for_each_generic(g_process_tracking_table,
				 _hashtbl_search_callback,
				 psRunningInodesToBan);
}

bool is_process_tracked(pid_t pid)
{
	struct pt_table_key key = { pid };
	return (NULL != hashtbl_get_generic(g_process_tracking_table, &key));
}

bool process_tracking_get_process(pid_t pid, struct ProcessTracking **procp)
{
	struct pt_table_key key = { pid };

	if (procp == NULL) {
		PR_DEBUG("procp is NULL will not get state for pid=%d", pid);
		return false;
	}

	*procp = (struct ProcessTracking *)hashtbl_get_generic(
		g_process_tracking_table, &key);
	if (!(*procp)) {
		PR_DEBUG("failed to find pid=%d", pid);
		return false;
	}

	PR_DEBUG_RATELIMITED("found pid=%d uid=%d inode=%llu",
			     (*procp)->pt_key.pid, (*procp)->uid,
			     (*procp)->inode);
	return true;
}

void create_process_start_event(struct task_struct *task)
{
	struct CB_EVENT *event = NULL;
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

	uint64_t ino = 0;
	char *pathname = NULL;
	uint64_t pathsz = 0;
	struct inode *inodep = NULL;
	struct dentry *dentryp = NULL;

	//
	// This is a valid process, allocate an event
	// Note: Since this function, create_process_start_event, is also used
	// inside interrupt handlers
	//       we must use the GFP_ATOMIC flag when calling
	//       cb_kmem_cache_alloc, hence the usage of
	//       logger_alloc_event_atomic
	//
	event = logger_alloc_event_atomic(CB_EVENT_TYPE_PROCESS_START, task);
	if (!event) {
		return;
	}

	//
	// Populate the event
	//
	event->processStart.parent = ppid;
	event->processStart.uid =
		process_tracking_should_track_user() ? uid : (uid_t)-1;
	event->processStart.start_action = CB_PROCESS_START_BY_EXEC;
	event->processStart.observed = false; // We want to tell user space this
		// is fake
	event->processStart.path[0] = 0;
	event->processStart.path[PATH_MAX] = 0;
	event->processStart.path_found = false;

	dentryp = get_dentry_from_mm(task->mm);
	if (dentryp) {
		inodep = get_inode_from_dentry(dentryp);
		if (inodep) {
			ino = inodep->i_ino;
		}
	}

	event->processStart.inode = ino;

	if (dentryp) {
		pathname = dentry_to_path(dentryp, event->processStart.path);
		if (IS_ERR(pathname)) {
			PRINTK(KERN_ERR, "Unable to get path from dentry.");
			pathname = NULL;
		}
		if (pathname) {
			pathsz = (&event->processStart.path[PATH_MAX] -
				  pathname);
			memmove(event->processStart.path, pathname, pathsz);
			event->processStart.path_found = true;
		}
	}

	if (!pathname) {
		strncpy(event->processStart.path, task->comm,
			sizeof(task->comm));
		event->processStart.path[sizeof(task->comm)] = 0;
	}

	//
	// Queue it to be sent to usermode
	//
	logger_submit_event(event);

	process_tracking_insert_process(pid, tid, ppid, uid, euid,
					CB_PROCESS_START_BY_FORK, task, event,
					true);

	PR_DEBUG("create_process_start event p=%d u=%d", pid, uid);
}

static int _show_process_tracking_table(struct HashTbl *hashTblp,
					struct HashTableNode *nodep, void *priv)
{
	struct ProcessTracking *procp = (struct ProcessTracking *)nodep;
	struct seq_file *m = (struct seq_file *)priv;

	seq_printf(m, "%10s | %6llu | %6llu | %6llu | %10llu |\n",
		   procp->taskp->comm, (uint64_t)procp->pt_key.pid,
		   (uint64_t)procp->tid, (uint64_t)procp->parent, procp->inode);

	return ACTION_CONTINUE;
}

int cb_proc_track_show_table(struct seq_file *m, void *v)
{
	seq_printf(m, "%10s | %6s | %6s | %6s | %10s |\n", "Name", "PID", "TID",
		   "PPID", "Inode");

	hashtbl_for_each_generic(g_process_tracking_table,
				 _show_process_tracking_table, m);

	return 0;
}

int cb_proc_track_show_stats(struct seq_file *m, void *v)
{
	seq_printf(m, "%22s | %6llu |\n", "Total Changes", g_pt_process_op_cnt);
	seq_printf(m, "%22s | %6llu |\n", "Process Creates",
		   g_pt_process_create);
	seq_printf(m, "%22s | %6llu |\n", "Process Forks",
		   g_pt_process_create_by_fork);
	seq_printf(m, "%22s | %6llu |\n", "Process Execs",
		   g_pt_process_create_by_exec);
	seq_printf(m, "%22s | %6llu |\n", "Process Exits", g_pt_process_exit);

	return 0;
}

// Similar to  process_tracking_remove_process but we don't need to operate by a
// key.
//
static int _hashtbl_clear_dead_callback(struct HashTbl *hashTblp,
					struct HashTableNode *nodep, void *priv)
{
	pid_t pid;
	int action = ACTION_CONTINUE;
	struct ProcessTracking *procp = NULL;
	struct CB_EVENT *event = NULL;

	if (!nodep) {
		goto out;
	}

	// nodep is really not type HashTableNode for this callback
	procp = (struct ProcessTracking *)nodep;
	pid = procp->pt_key.pid;

	if (cb_find_task(pid) == NULL) {
		action = ACTION_DELETE;

		// Just as process_tracking_remove_process calls it

		event = logger_alloc_event_notask(CB_EVENT_TYPE_PROCESS_EXIT,
						  pid, GFP_ATOMIC);
		if (event) {
			logger_submit_event(event);
		}
	}

out:
	return action;
}

static void process_tracking_for_each_clear_dead(void)
{
	hashtbl_for_each_generic(g_process_tracking_table,
				 _hashtbl_clear_dead_callback, NULL);
}

// We could schedule this to be flushed/ran more immediately if the
// hashtable was gets too large before the next scheduled run.
static void process_tracking_clear_dead(struct work_struct *work)
{
	process_tracking_for_each_clear_dead();
	schedule_delayed_work(&g_proc_clear_dead_work, CLEAR_DEAD_JIFFIES);
}
