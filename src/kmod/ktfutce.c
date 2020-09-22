/*
 * Copyright 2018-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "priv.h"
#include "process-tracking.h"
#include <linux/kthread.h>
#include <linux/wait.h>

//
// ktfutce handles a queue of Fork events and the tgid in question.
// We may want to pre-allocate a process tracking table entry and
// send to here as well and fill in all the data.
//
// With our current fork hook we cannot safely lookup the new
// task yet. So we throw the job into our kthread via a
// wait queue. By the time this thread wakes the new task
// will highly likely be available.
//

static DECLARE_WAIT_QUEUE_HEAD(clone_wait);
struct clone_struct {
	struct task_struct *task;
	struct list_head head;
	spinlock_t lock;
	unsigned long len;
};
static struct clone_struct clone_queue = { .task = NULL };

struct clone_event {
	struct list_head list;
	pid_t pid;
	struct CB_EVENT *event;
};

static int ktfutce_thread(void *arg);

int ktfutce_register(void)
{
	int ret = 0;

	memset(&clone_queue, 0, sizeof(clone_queue));
	INIT_LIST_HEAD(&clone_queue.head);
	spin_lock_init(&clone_queue.lock);

	clone_queue.task = kthread_run(ktfutce_thread, NULL, "cb_ktfutce");
	if (IS_ERR(clone_queue.task)) {
		ret = PTR_ERR(clone_queue.task);
		clone_queue.task = NULL;
	}
	return ret;
}

// Probably should be called before logger shutdown
void ktfutce_shutdown(void)
{
	if (clone_queue.task) {
		struct task_struct *task = clone_queue.task;
		clone_queue.task = NULL;
		wake_up_interruptible(&clone_wait);
		kthread_stop(task);
	}
}

// Enqueue a fork event and ask the kthread to work on it
int ktfutce_add_pid(pid_t pid, struct CB_EVENT *event, gfp_t mode)
{
	unsigned long flags;
	struct clone_event *clone_event = NULL;

	if (!clone_queue.task || !pid) {
		return -EINVAL;
	}

	clone_event = kzalloc(sizeof(*clone_event), mode);
	if (!clone_event) {
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&clone_event->list);
	clone_event->pid = pid;
	clone_event->event = event;

	spin_lock_irqsave(&clone_queue.lock, flags);
	list_add_tail(&clone_event->list, &clone_queue.head);
	clone_queue.len += 1;
	spin_unlock_irqrestore(&clone_queue.lock, flags);
	wake_up_interruptible(&clone_wait);

	return 0;
}

static inline struct clone_event *clone_shift(void)
{
	unsigned long flags;
	struct clone_event *clone_event = NULL;

	spin_lock_irqsave(&clone_queue.lock, flags);
	if (list_empty(&clone_queue.head)) {
		spin_unlock_irqrestore(&clone_queue.lock, flags);
		return NULL;
	}

	clone_event =
		list_first_entry(&clone_queue.head, struct clone_event, list);
	if (clone_event) {
		clone_queue.len -= 1;
		list_del_init(&clone_event->list);
	}
	spin_unlock_irqrestore(&clone_queue.lock, flags);

	return clone_event;
}

static int ktfutce_thread(void *arg)
{
	while (!kthread_should_stop()) {
		pid_t pid;
		struct task_struct *task = NULL;
		struct clone_event *clone_event = NULL;
		struct CB_EVENT *event = NULL;

		clone_event = clone_shift();
		if (!clone_event) {
			goto wait;
		}

		pid = clone_event->pid;
		event = clone_event->event;
		kfree(clone_event);
		clone_event = NULL;

		task = cb_find_task(pid);

		// We may not want these to do irq spinlocks
		if (task && !(task->flags & PF_KTHREAD) && pid_alive(task) &&
		    pid == task->tgid) {
			// Depending on how safe it is to fill in the event
			// data we may want to do this work here.
			// This would mean less table lookups.
			if (event) {
				logger_submit_event(event);
			}
		} else {
			process_tracking_remove_process(pid);
			if (event) {
				logger_free_event_on_error(event);
			}
		}
	wait:
		wait_event_interruptible_timeout(clone_wait,
						 (clone_queue.task == NULL ||
						  clone_queue.len > 0),
						 msecs_to_jiffies(500));
	}

	return 0;
}
