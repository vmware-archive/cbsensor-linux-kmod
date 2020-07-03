/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_PROC)
#include "priv.h"

pid_t gettid(struct task_struct *task)
{
	return task->pid; // this is the thread id
}

pid_t getpid(struct task_struct *task)
{
	return task->tgid;
}

pid_t getppid(struct task_struct *task)
{
	if (task->real_parent) // @@review: use parent?
	{
		return getpid(task->real_parent);
	}
	PR_DEBUG("no parent for task %d", getpid(task));
	return -1;
}

struct task_struct *cb_find_task(pid_t pid)
{
	struct task_struct *task = NULL;

	rcu_read_lock();
	task = CB_RESOLVED(find_task_by_vpid)(pid);
	rcu_read_unlock();

	return task;
}

void get_starttime(struct timespec *start_time)
{
	// to interpret see http://www.fieldses.org/~bfields/kernel/time.txt
	struct timespec current_time;

	getnstimeofday(&current_time);
	set_normalized_timespec(start_time, current_time.tv_sec,
				current_time.tv_nsec);
}
