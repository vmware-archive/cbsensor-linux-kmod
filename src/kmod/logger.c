/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS DS_LOG
#include "priv.h"
#include <linux/gfp.h>
#include <linux/time.h>

#include "../cbevent/src/CB_EVENT_FILTER.h"

struct CB_EVENT_DATA cb_event_data = { 0 };

bool user_comm_initialize(void);
void user_comm_shutdown(void);
int user_comm_send_event(struct CB_EVENT *);
int user_comm_send_event_atomic(struct CB_EVENT *);

uint64_t to_windows_timestamp(struct timespec *tv)
{
	return ((uint64_t)tv->tv_sec * (uint64_t)10000000) +
	       (uint64_t)116444736000000000 + (tv->tv_nsec / 100);
}

void free_event_cache(struct CB_EVENT *event)
{
	if (!cb_event_data.cb_event_cache) {
		return;
	}

	if (!event) {
		return;
	}

	kmem_cache_free(cb_event_data.cb_event_cache, event);
	atomic64_dec(&(cb_event_data.eventAllocs));
}

static void logger_free_event(struct CB_EVENT *event)
{
	if (!cb_event_data.cb_event_cache) {
		return;
	}

	if (!event) {
		return;
	}

	kmem_cache_free(cb_event_data.cb_event_cache, event);
	atomic64_dec(&(cb_event_data.eventAllocs));
}

static void getprocinfo(struct task_struct *task,
			struct CB_EVENT_PROCESS_INFO *procInfo)
{
	if (task != NULL) {
		procInfo->pid = getpid(task);
	}

	get_starttime(&procInfo->process_start_time_unix);
	getnstimeofday(&procInfo->event_time_unix);
	procInfo->process_start_time =
		to_windows_timestamp(&procInfo->process_start_time_unix);
	procInfo->event_time = to_windows_timestamp(&procInfo->event_time_unix);
}

bool should_log(enum CB_EVENT_TYPE eventType)
{
	switch (eventType) {
	case CB_EVENT_TYPE_PROCESS_START:
	case CB_EVENT_TYPE_PROCESS_EXIT:
		return (g_eventFilter & CB_EVENT_FILTER_PROCESSES) ==
		       CB_EVENT_FILTER_PROCESSES;

	case CB_EVENT_TYPE_MODULE_LOAD:
		return (g_eventFilter & CB_EVENT_FILTER_MODULE_LOADS) ==
		       CB_EVENT_FILTER_MODULE_LOADS;

	case CB_EVENT_TYPE_FILE_CREATE:
	case CB_EVENT_TYPE_FILE_DELETE:
	case CB_EVENT_TYPE_FILE_WRITE:
	case CB_EVENT_TYPE_FILE_CLOSE:
		return (g_eventFilter & CB_EVENT_FILTER_FILEMODS) ==
		       CB_EVENT_FILTER_FILEMODS;

	case CB_EVENT_TYPE_NET_CONNECT_PRE:
	case CB_EVENT_TYPE_NET_CONNECT_POST:
	case CB_EVENT_TYPE_NET_ACCEPT:
	case CB_EVENT_TYPE_DNS_RESPONSE:
		return (g_eventFilter & CB_EVENT_FILTER_NETCONNS) ==
		       CB_EVENT_FILTER_NETCONNS;

	case CB_EVENT_TYPE_PROCESS_BLOCKED:
	case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
	case CB_EVENT_TYPE_HEARTBEAT:
	case CB_EVENT_TYPE_WEB_PROXY:
		return true;

	default:
		PRINTK(KERN_WARNING, "Unknown shouldlog event type %d",
		       eventType);
		return true;
	}
}

bool shouldExcludeByUID(uid_t uid)
{
	if (g_cb_server_uid == uid) {
		return true;
	}

	return cbIngoreUid(uid);
}

struct CB_EVENT *logger_alloc_event_notask(enum CB_EVENT_TYPE eventType,
					   pid_t pid, gfp_t allocType)
{
	struct CB_EVENT *event = NULL;
	uid_t uid;

	if (!cb_event_data.cb_event_cache) {
		goto out;
	}
	if (!should_log(eventType)) {
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	uid = current_cred()->uid.val;
#else
	uid = current_cred()->uid;
#endif
	if (shouldExcludeByUID(uid)) {
		goto out;
	}

	event = cb_kmem_cache_alloc(cb_event_data.cb_event_cache, allocType);
	if (!event) {
		PRINTK(KERN_WARNING, "Error allocating event type %d",
		       eventType);
		goto out;
	}

	atomic64_inc(&(cb_event_data.eventAllocs));
	event->eventType = eventType;
	event->canary = 0;
	getprocinfo(NULL, &event->procInfo);
	event->procInfo.pid = pid;

out:
	return event;
}

static struct CB_EVENT *
logger_alloc_event_internal(enum CB_EVENT_TYPE eventType,
			    struct task_struct *task, gfp_t allocType)
{
	struct CB_EVENT *event = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	uid_t uid = current_cred()->uid.val;
#else
	uid_t uid = current_cred()->uid;
#endif

	if (!cb_event_data.cb_event_cache) {
		goto Exit;
	}

	if (should_log(eventType) == false) {
		goto Exit;
	}

	if (shouldExcludeByUID(uid) == true) {
		goto Exit;
	}

	event = (struct CB_EVENT *)cb_kmem_cache_alloc(
		cb_event_data.cb_event_cache, allocType);

	if (event) {
		atomic64_inc(&(cb_event_data.eventAllocs));
		event->eventType = eventType;
		event->canary = 0;
		getprocinfo(task, &event->procInfo);
		goto Exit;
	}

	PRINTK(KERN_WARNING, "Error allocating event type %d", eventType);
Exit:
	return event;
}

struct CB_EVENT *logger_alloc_event_atomic(enum CB_EVENT_TYPE eventType,
					   struct task_struct *task)
{
	return logger_alloc_event_internal(eventType, task, GFP_ATOMIC);
}

struct CB_EVENT *logger_alloc_event(enum CB_EVENT_TYPE eventType,
				    struct task_struct *task)
{
	return logger_alloc_event_internal(eventType, task, GFP_KERNEL);
}

void logger_submit_event(struct CB_EVENT *event)
{
	user_comm_send_event(event);
}

void logger_submit_event_atomic(struct CB_EVENT *event)
{
	user_comm_send_event_atomic(event);
}

void logger_free_event_on_error(struct CB_EVENT *event)
{
	logger_free_event(event);
}

bool logger_initialize(void)
{
	PR_DEBUG("Initializing Logger");
	PR_DEBUG("CB_EVENT size is %ld (0x%lx)", sizeof(struct CB_EVENT),
		 sizeof(struct CB_EVENT));

	cb_event_data.cb_event_cache =
		kmem_cache_create("cb_event_cache", sizeof(struct CB_EVENT), 0,
				  SLAB_HWCACHE_ALIGN, NULL);
	if (!cb_event_data.cb_event_cache) {
		PRINTK(KERN_ERR, "failed to allocate event cache");
		return false;
	}

	if (user_comm_initialize() == false) {
		PRINTK(KERN_ERR, "failed to initialize user communications");
		return false;
	}

	return true;
}

void logger_shutdown(void)
{
	user_comm_shutdown();
	if (cb_event_data.cb_event_cache) {
		kmem_cache_destroy(cb_event_data.cb_event_cache);
	}
}
