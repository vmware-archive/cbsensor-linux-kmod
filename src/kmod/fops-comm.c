/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

//
/// \file fops-comm.c
/// \desc This file is designed to replace the old netlink communications
/// which was under the GPL.
/// TODO: Investigate returning to netlink now this the module is GPL
//
#define DS_MYSUBSYS DS_COMMS
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
// Kernels pre 2.6.33 used an old version of kfifo
#if LINUX_VERSION_CODE < 0x020621
#include <linux/kfifo-new.h>
#else
#include <linux/kfifo.h>
#endif
#include <asm/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "cb-banning.h"
#include "cb-isolation.h"
#include "hash-table-generic.h"
#include "priv.h"

#include "../cbevent/src/CB_DRIVER_REQUEST.h"
#include "../cbevent/src/CB_EVENT_DYNAMIC.h"
#include "../cbevent/src/CB_PROTECTION_CONTROL.h"
#include "../cbevent/src/CB_TRUSTED_PATH.h"

#include "InodeState.h"

const char DRIVER_NAME[] = "cbsensor";
#define MINOR_COUNT 1
#define MSG_QUEUE_SIZE 8192 // Must be power of 2
ssize_t KF_LEN = sizeof(struct CB_EVENT); // This needs to be sizeof(whatever we
	// store in kfifo)

int device_open(struct inode *, struct file *);
int device_release(struct inode *, struct file *);
ssize_t device_read(struct file *f, char __user *buf, size_t count,
		    loff_t *offset);
unsigned int device_poll(struct file *, struct poll_table_struct *);
static long device_unlocked_ioctl(struct file *filep, unsigned int cmd,
				  unsigned long arg);

struct file_operations driver_fops = {
	.owner = THIS_MODULE,
	.read = device_read,
	.poll = device_poll,
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_unlocked_ioctl,
};

// Our device special major number
static dev_t g_maj_t = 0;
struct cdev cb_cdev;

static DECLARE_KFIFO_PTR(msg_queue_pri0, struct CB_EVENT *);
static DECLARE_KFIFO_PTR(msg_queue_pri1, struct CB_EVENT *);

#define MAX_VALID_INTERVALS 60
#define MAX_INTERVALS 62
#define NUM_STATS 17
#define EVENT_STATS 13
#define MEM_START EVENT_STATS
#define MEM_STATS (EVENT_STATS + 4)
struct CB_EVENT_STATS {
	// This is a circular array of elements were each element is an
	// increasing sum from the
	//  previous element. You can always get the sum of any two elements,
	//  and divide by the number of elements between them to yield the
	//  average. tx_queued_pri0; tx_queued_pri1; tx_dropped; tx_total;
	//  tx_other
	//  tx_process
	//  tx_modload
	//  tx_file
	//  tx_net
	//  tx_dns
	//  tx_proxy
	//  tx_block
	atomic64_t stats[MAX_INTERVALS][NUM_STATS];
	struct timespec time[MAX_INTERVALS];

	// These are live counters that rise and fall as events are generated.
	// This variable
	//  will be added to the stats end the end of each interval.
	atomic64_t tx_ready_pri0;
	atomic64_t tx_ready_pri1;
	atomic64_t tx_ready_prev0;
	atomic64_t tx_ready_prev1;

	// The current index into the list
	atomic_t curr;

	// The number of times the list has carried over. (This helps us
	// calculate the average
	//  later by knowing how many are valid.)
	atomic_t validStats;
};

const struct {
	const char *name;
	const char *str_format;
	const char *num_format;
} STAT_STRINGS[] = { { "Total Queued", " %12s ||", " %12d ||" },
		     { "Queued in P0", " %12s |", " %12d |" },
		     { "Queued in P1", " %12s |", " %12d |" },
		     { "Dropped", " %7s |", " %7d |" },
		     { "All", " %7s |", " %7d |" },
		     { "Process", " %7s |", " %7d |" },
		     { "Modload", " %7s |", " %7d |" },
		     { "File", " %7s |", " %7d |" },
		     { "Net", " %7s |", " %7d |" },
		     { "DNS", " %7s |", " %7d |" },
		     { "Proxy", " %7s |", " %7d |" },
		     { "Blocked", " %7s |", " %7d |" },
		     { "Other", " %7s |", " %7d |" },
		     { "User", " %10s |", " %10d |" },
		     { "User Peak", " %10s |", " %10d |" },
		     { "Kernel", " %7s |", " %7d |" },
		     { "Kernel Peak", " %12s |", " %12d |" } };

struct CB_EVENT_STATS cb_event_stats;

#define current_stat (cb_event_stats.curr)
#define valid_stats (cb_event_stats.validStats)
#define tx_ready_pri0 (cb_event_stats.tx_ready_pri0)
#define tx_ready_pri1 (cb_event_stats.tx_ready_pri1)
#define tx_ready_prev0 (cb_event_stats.tx_ready_prev0)
#define tx_ready_prev1 (cb_event_stats.tx_ready_prev1)
#define tx_queued_t (cb_event_stats.stats[atomic_read(&current_stat)][0])
#define tx_queued_pri0 (cb_event_stats.stats[atomic_read(&current_stat)][1])
#define tx_queued_pri1 (cb_event_stats.stats[atomic_read(&current_stat)][2])
#define tx_dropped (cb_event_stats.stats[atomic_read(&current_stat)][3])
#define tx_total (cb_event_stats.stats[atomic_read(&current_stat)][4])
#define tx_process (cb_event_stats.stats[atomic_read(&current_stat)][5])
#define tx_modload (cb_event_stats.stats[atomic_read(&current_stat)][6])
#define tx_file (cb_event_stats.stats[atomic_read(&current_stat)][7])
#define tx_net (cb_event_stats.stats[atomic_read(&current_stat)][8])
#define tx_dns (cb_event_stats.stats[atomic_read(&current_stat)][9])
#define tx_proxy (cb_event_stats.stats[atomic_read(&current_stat)][10])
#define tx_block (cb_event_stats.stats[atomic_read(&current_stat)][11])
#define tx_other (cb_event_stats.stats[atomic_read(&current_stat)][12])

#define mem_user (cb_event_stats.stats[atomic_read(&current_stat)][13])
#define mem_user_peak (cb_event_stats.stats[atomic_read(&current_stat)][14])
#define mem_kernel (cb_event_stats.stats[atomic_read(&current_stat)][15])
#define mem_kernel_peak (cb_event_stats.stats[atomic_read(&current_stat)][16])

bool have_reader = false;
uint64_t dev_spinlock;

DECLARE_WAIT_QUEUE_HEAD(wq);

extern void free_event_cache(struct CB_EVENT *event);

#define STAT_INTERVAL 15
static struct delayed_work stats_work;
static void stats_work_task(struct work_struct *work);
static uint32_t g_stats_work_delay;

bool user_comm_initialize(void)
{
	int i;
	size_t kernel_mem;

	cb_initspinlock(&dev_spinlock);
	// Allocate kfifo for handling messages with the daemon
	TRY_STEP_DO(CDEV_INIT,
		    0 == kfifo_alloc(&msg_queue_pri0, MSG_QUEUE_SIZE,
				     GFP_KERNEL),
		    { PRINTK(KERN_ERR, "kfifo_alloc failed"); });
	TRY_STEP_DO(FIFO_ALLOC,
		    0 == kfifo_alloc(&msg_queue_pri1, MSG_QUEUE_SIZE,
				     GFP_KERNEL),
		    { PRINTK(KERN_ERR, "kfifo_alloc failed"); });

	atomic_set(&current_stat, 0);
	atomic_set(&valid_stats, 0);
	atomic64_set(&tx_ready_pri0, 0);
	atomic64_set(&tx_ready_pri1, 0);
	for (i = 0; i < NUM_STATS; ++i) {
		// We make sure the first and last interval are 0 for the
		// average calculations
		atomic64_set(&cb_event_stats.stats[0][i], 0);
		atomic64_set(&cb_event_stats.stats[MAX_INTERVALS - 1][i], 0);
	}
	getnstimeofday(&cb_event_stats.time[0]);
	kernel_mem = hashtbl_get_memory();
	atomic64_set(&mem_kernel, kernel_mem);
	atomic64_set(&mem_kernel_peak, kernel_mem);

	// Initialize a workque struct to police the hashtable
	g_stats_work_delay = msecs_to_jiffies(STAT_INTERVAL * 1000);
	INIT_DELAYED_WORK(&stats_work, stats_work_task);
	schedule_delayed_work(&stats_work, g_stats_work_delay);

	return true;

// Error handling
// Clean up all device node allocations and return false here
// to abort the driver init process. We need to do the cleanup,
// otherwise we end up in a situation when we have a device node created,
// but the driver is unloaded, so when cbdaemon calls open()
// for this device node it triggers a kernel panic.
CATCH_FIFO_ALLOC:
	kfifo_free(&msg_queue_pri0);

CATCH_CDEV_INIT:
	cb_destroyspinlock(&dev_spinlock);
	return false;
}

bool user_devnode_init(void)
{
	const unsigned int MINOR_FIRST = 0;
	int maj_no;

	// Allocate Major / Minor number of device special file
	TRY_STEP_DO(
		DEVNUM_ALLOC,
		alloc_chrdev_region(&g_maj_t, MINOR_FIRST, MINOR_COUNT,
				    DRIVER_NAME) >= 0,
		{
			PRINTK(KERN_ERR,
			       "Failed allocating character device region.");
		});

	maj_no = MAJOR(g_maj_t);
	cdev_init(&cb_cdev, &driver_fops);
	TRY_STEP_DO(CHRDEV_ALLOC, cdev_add(&cb_cdev, g_maj_t, 1) >= 0,
		    { PRINTK(KERN_ERR, "cdev_add failed"); });

	return true;

CATCH_CHRDEV_ALLOC:
	unregister_chrdev_region(g_maj_t, MINOR_COUNT);
	cdev_del(&cb_cdev);

CATCH_DEVNUM_ALLOC:
	PRINTK(KERN_ERR, "failed to initialize user dev node");
	return false;
}

void user_devnode_close(void)
{
	cdev_del(&cb_cdev);
	unregister_chrdev_region(g_maj_t, MINOR_COUNT);
}

void user_comm_shutdown(void)
{
	struct CB_EVENT *msg = NULL;

	cancel_delayed_work(&stats_work);

	cb_spinlock(&dev_spinlock);
	while (atomic64_read(&tx_ready_pri0) != 0) {
		if (kfifo_get(&msg_queue_pri0, &msg)) {
			free_event_cache(msg);
			atomic64_dec(&tx_ready_pri0);
		}
	}
	while (atomic64_read(&tx_ready_pri1) != 0) {
		if (kfifo_get(&msg_queue_pri1, &msg)) {
			free_event_cache(msg);
			atomic64_dec(&tx_ready_pri1);
		}
	}
	kfifo_free(&msg_queue_pri0);
	kfifo_free(&msg_queue_pri1);
	cb_spinunlock(&dev_spinlock);
	cb_destroyspinlock(&dev_spinlock);
}

// Add item onto kfifo
int user_comm_send_event_atomic(struct CB_EVENT *msg)
{
	unsigned int enqueued = 0;
	atomic64_t *tx_ready = NULL;
	if (!have_reader) {
		free_event_cache(msg);
		return -1;
	}

	cb_spinlock(&dev_spinlock);
	switch (msg->eventType) {
	case CB_EVENT_TYPE_PROCESS_START:
	case CB_EVENT_TYPE_PROCESS_EXIT:
	case CB_EVENT_TYPE_PROCESS_BLOCKED:
	case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
		enqueued = kfifo_put(&msg_queue_pri0,
				     (const struct CB_EVENT **)&msg);
		tx_ready = &tx_ready_pri0;
		break;
	default:
		enqueued = kfifo_put(&msg_queue_pri1,
				     (const struct CB_EVENT **)&msg);
		tx_ready = &tx_ready_pri1;
		break;
	}
	cb_spinunlock(&dev_spinlock);

	if (enqueued) {
		atomic64_inc(tx_ready);
		PR_DEBUG_RATELIMITED("send_event_atomic %p %u %lu", msg,
				     enqueued, atomic64_read(tx_ready));
		wake_up(&wq);
	} else {
		atomic64_inc(&tx_dropped);
		PR_DEBUG("Failed insertion atomic: %u %lu", enqueued,
			 atomic64_read(tx_ready));
		free_event_cache(msg);
	}
	return 0;
}

int user_comm_send_event(struct CB_EVENT *msg)
{
	return user_comm_send_event_atomic(msg);
}

// Remove item from kfifo
ssize_t device_read(struct file *f, char __user *ubuf, size_t count,
		    loff_t *offset)
{
	struct CB_EVENT *msg = NULL;
	int rc = 0;
	ssize_t len = 0;
	atomic64_t *tx_ready = NULL;
	uint64_t qlen_a;
	uint64_t qlen_b;
	uint64_t qlen_a_pct;
	uint64_t qlen_b_pct;

	PR_DEBUG_RATELIMITED("start read");

	// You *must* ask for at least 1 packet
	if (count < KF_LEN) {
		PR_DEBUG("size mismatch count=%ld KF_LEN=%ld", count, KF_LEN);
		return -ENOMEM;
	}

	qlen_a = atomic64_read(&tx_ready_pri0);
	qlen_b = atomic64_read(&tx_ready_pri1);

	if (qlen_a == 0 && qlen_b == 0) {
		PR_DEBUG("empty queue");
		return -ENOMEM;
	}

	// Calculate the percentage of used capacity
	qlen_a_pct = (qlen_a * 100) / MSG_QUEUE_SIZE;
	qlen_b_pct = (qlen_b * 100) / MSG_QUEUE_SIZE;

	cb_spinlock(&dev_spinlock);

	// To avoid starvation we need to not only service the queues based on
	// priority, but also by capacity. The typical rules, pri0 out ranks
	// pri1, hold true except when utilization hits 90%. At that point,
	// either we're likely being flooded with events and may be able to
	// reduce some pressue by tweeking the priorities a bit.

	if (qlen_a_pct >= 90 || // if utilization is at 90% for 'a', short
	    // circuit and handle it
	    (qlen_a != 0 && qlen_b_pct < 90)) // otherwise, make sure we have an
	// event and process it if 'b' is
	// not critical
	{
		tx_ready = &tx_ready_pri0;
		rc = kfifo_get(&msg_queue_pri0, &msg);
	} else {
		tx_ready = &tx_ready_pri1;
		rc = kfifo_get(&msg_queue_pri1, &msg);
	}
	cb_spinunlock(&dev_spinlock);

	if (!rc) {
		PR_DEBUG("failed to dequeue event");
		return -ENOMEM;
	}

	atomic64_dec(tx_ready);

	if (!msg) {
		PR_DEBUG("dequeued msg is NULL");
		return -ENOMEM;
	}

	atomic64_inc(&tx_total);

	switch (msg->eventType) {
	case CB_EVENT_TYPE_PROCESS_START:
	case CB_EVENT_TYPE_PROCESS_EXIT:
		atomic64_inc(&tx_process);
		break;

	case CB_EVENT_TYPE_MODULE_LOAD:
		atomic64_inc(&tx_modload);
		break;

	case CB_EVENT_TYPE_FILE_CREATE:
	case CB_EVENT_TYPE_FILE_DELETE:
	case CB_EVENT_TYPE_FILE_WRITE:
	case CB_EVENT_TYPE_FILE_CLOSE:
		atomic64_inc(&tx_file);
		break;

	case CB_EVENT_TYPE_NET_CONNECT_PRE:
	case CB_EVENT_TYPE_NET_CONNECT_POST:
	case CB_EVENT_TYPE_NET_ACCEPT:
		atomic64_inc(&tx_net);
		break;

	case CB_EVENT_TYPE_DNS_RESPONSE:
		atomic64_inc(&tx_dns);
		break;

	case CB_EVENT_TYPE_WEB_PROXY:
		atomic64_inc(&tx_proxy);
		break;

	case CB_EVENT_TYPE_PROCESS_BLOCKED:
	case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
		atomic64_inc(&tx_block);
		break;

	case CB_EVENT_TYPE_PROC_ANALYZE:
	case CB_EVENT_TYPE_HEARTBEAT:
	case CB_EVENT_TYPE_MAX:
	case CB_EVENT_TYPE_UNKNOWN:
	default:
		atomic64_inc(&tx_other);
		break;
	}

	rc = copy_to_user(ubuf, msg, KF_LEN);
	if (rc) {
		PR_DEBUG("copy to user failed rc=%d", rc);
		len = -ENXIO;
	} else {
		*offset = 0;
		len = KF_LEN;
		PR_DEBUG_RATELIMITED("read=%ld qlen_a=%llu qlen_b=%llu", len,
				     qlen_a, qlen_b);
	}

	free_event_cache(msg);
	return len;
}

int device_open(struct inode *inode, struct file *filp)
{
	if (have_reader) {
		PR_DEBUG("can only have one connection");
		return -EMFILE;
	}

	have_reader = true;
	return nonseekable_open(inode, filp);
}

int device_release(struct inode *inode, struct file *filp)
{
	have_reader = false;
	return 0;
}

unsigned int device_poll(struct file *filp, struct poll_table_struct *pts)
{
	uint64_t qlen;

	// Check if data is available and lets go
	qlen = atomic64_read(&tx_ready_pri0) + atomic64_read(&tx_ready_pri1);

	if (qlen != 0) {
		PR_DEBUG_RATELIMITED("msg available qlen=%llu", qlen);
		goto data_avail;
	}

	// We should call poll_wait here if we want the kernel to actually
	// sleep when waiting for us.
	PR_DEBUG_RATELIMITED("waiting for data");
	poll_wait(filp, &wq, pts);

	qlen = atomic64_read(&tx_ready_pri0) + atomic64_read(&tx_ready_pri1);

	if (qlen != 0) {
		PR_DEBUG_RATELIMITED("msg available qlen=%llu", qlen);
		goto data_avail;
	}

	PR_DEBUG_RATELIMITED("msg queued qlen=%llu", qlen);

data_avail:
	// We should also return POLLHUP if we ever desire to shutdown
	return (qlen != 0 ? (POLLIN | POLLRDNORM) : 0);
}

static long device_unlocked_ioctl(struct file *filep, unsigned int cmd,
				  unsigned long arg)
{
	unsigned long data = 0;
	void *page = 0;

	// Shift to avoid Linux IOW|IOR bits.
	cmd >>= 2;

	if (!arg) {
		PRINTK(KERN_ERR, "arg null");
		return -ENOMEM;
	}

	if ((cmd == CB_DRIVER_REQUEST_SET_BANNED_INODE) ||
	    (cmd == CB_DRIVER_REQUEST_CLR_BANNED_INODE) ||
	    (cmd == CB_DRIVER_REQUEST_SET_TRUSTED_PATH)) {
		page = (void *)__get_free_page(GFP_KERNEL);
		if (!page) {
			PRINTK(KERN_ERR, "alloc failed cmd=%d", cmd);
			return -ENOMEM;
		}
	} else if (cmd == CB_DRIVER_REQUEST_ISOLATION_MODE_CONTROL) {
		// We are really passed a CB_EVENT_DYNAMIC object that holds a
		// pointer to the real
		//  CB_ISOLATION_MODE_CONTROL struct and its size.  We get this
		//  struct now and pass the pointer and size to the isolation
		//  logic later.  It will call copy_from_user again to get the
		//  real data.
		struct CB_EVENT_DYNAMIC dynControl;
		if (copy_from_user(&dynControl, (void *)arg,
				   sizeof(struct CB_EVENT_DYNAMIC))) {
			PRINTK(KERN_ERR, "failed to copy arg");
			return -ENOMEM;
		}
		data = dynControl.size;
		arg = dynControl.data;
	} else {
		if (copy_from_user(&data, (void *)arg, sizeof(data))) {
			PRINTK(KERN_ERR, "failed to copy arg");
			return -ENOMEM;
		}
	}

	switch (cmd) {
	case CB_DRIVER_REQUEST_APPLY_FILTER: {
		uint32_t eventFilter = (uint32_t)data;
		PR_DEBUG("Received filter 0x%X currfilter 0x%X", eventFilter,
			 g_eventFilter);
		if (eventFilter != g_eventFilter) {
			PRINTK(KERN_INFO, "+Applying filter 0x%X", eventFilter);
			g_eventFilter = eventFilter;
		}
	} break;

	case CB_DRIVER_REQUEST_IGNORE_UID: {
		uid_t uid = (uid_t)data;
		PR_DEBUG("Received uid=%u", uid);
		cbSetIgnoredUid(uid);
	} break;

	case CB_DRIVER_REQUEST_IGNORE_SERVER: {
		uid_t uid = (uid_t)data;
		PR_DEBUG("Received server uid curr=%u new%u", uid,
			 g_cb_server_uid);
		if (uid != g_cb_server_uid) {
			PRINTK(KERN_INFO, "+Setting CB server UID=%u", uid);
			g_cb_server_uid = uid;
		}
	} break;

	case CB_DRIVER_REQUEST_IGNORE_PID: {
		pid_t pid = (pid_t)data;
		PR_DEBUG("Received trusted pid=%u", pid);
		cbSetIgnoredProcess(pid);
	} break;

	case CB_DRIVER_REQUEST_ISOLATION_MODE_CONTROL: {
		CbProcessIsolationSetMode((void *)arg, data);
	} break;

	case CB_DRIVER_REQUEST_HEARTBEAT: {
		struct CB_EVENT *event = NULL;
		struct task_struct *task = current;

		struct CB_EVENT_HEARTBEAT heartbeat;
		if (copy_from_user(&heartbeat, (void *)arg,
				   sizeof(heartbeat))) {
			PRINTK(KERN_ERR, "failed to copy arg");
			return -ENOMEM;
		}

		PR_DEBUG("Got a heartbeat request.");
		event = logger_alloc_event(CB_EVENT_TYPE_HEARTBEAT, task);
		if (NULL == event) {
			PRINTK(KERN_ERR,
			       "Unable to alloc CB_EVENT_TYPE_HEARTBEAT.");
		} else {
			atomic64_set(&mem_user, heartbeat.user_memory);
			atomic64_set(&mem_user_peak,
				     heartbeat.user_memory_peak);
			event->heartbeat.user_memory = heartbeat.user_memory;
			event->heartbeat.user_memory_peak =
				heartbeat.user_memory_peak;
			event->heartbeat.kernel_memory =
				atomic64_read(&mem_kernel);
			event->heartbeat.kernel_memory_peak =
				atomic64_read(&mem_kernel_peak);
			logger_submit_event(event);
		}
	} break;

	case CB_DRIVER_REQUEST_SET_BANNED_INODE: {
		struct CB_PROTECTION_CONTROL *protectionData =
			(struct CB_PROTECTION_CONTROL *)page;
		int i;

		if (copy_from_user(page, (void *)arg,
				   sizeof(struct CB_PROTECTION_CONTROL))) {
			PRINTK(KERN_ERR, "failed to copy arg");
			free_page((long unsigned int)page);
			return -ENOMEM;
		}

		for (i = 0; i < protectionData->count; ++i) {
			if (protectionData->data[i].action == InodeBanned) {
				cbSetBannedProcessInode(
					protectionData->data[i].inode);
				PR_DEBUG("banned inode: %llu",
					 protectionData->data[i].inode);
			}
		}
		free_page((long unsigned int)page);
	} break;

	case CB_DRIVER_REQUEST_PROTECTION_ENABLED: {
		cbSetProtectionState((uint32_t)data);
	}

	case CB_DRIVER_REQUEST_CLR_BANNED_INODE: {
		cbClearAllBans();
		free_page((long unsigned int)page);
	} break;

	case CB_DRIVER_REQUEST_SET_TRUSTED_PATH: {
		struct CB_TRUSTED_PATH *pathData =
			(struct CB_TRUSTED_PATH *)page;
		if (copy_from_user(page, (void *)arg,
				   sizeof(struct CB_TRUSTED_PATH))) {
			PRINTK(KERN_ERR, "failed to copy arg");
			free_page((long unsigned int)page);
			return -ENOMEM;
		}

		PR_DEBUG("pathData=%p path=%s", pathData, pathData->path);
		free_page((long unsigned int)page);
	} break;

	default:
		PRINTK(KERN_WARNING, "Unknown request type %d", cmd);
		break;
	}

	return 0l;
}

static void stats_work_task(struct work_struct *work)
{
	uint32_t curr = atomic_read(&cb_event_stats.curr);
	uint32_t next = (curr + 1) % MAX_INTERVALS;
	uint64_t ready0 = atomic64_read(&tx_ready_pri0);
	uint64_t ready1 = atomic64_read(&tx_ready_pri1);
	uint64_t prev0 = atomic64_read(&tx_ready_prev0);
	uint64_t prev1 = atomic64_read(&tx_ready_prev1);
	int i;
	size_t kernel_mem;
	size_t kernel_mem_peak;

	// I am not strictly speaking doing this operation atomicly.  This means
	// there is a
	//  chance that a counter will be missed.  I am willing to allow that
	//  for the sake of performance.

	// tx_ready_X are live counters that rise and fall as events are
	// generated. Add whatever
	//  is new in this variable to the current stat.
	if (ready0 > prev0) {
		atomic64_add(ready0 - prev0, &tx_queued_pri0);
	}
	if (ready1 > prev1) {
		atomic64_add(ready1 - prev1, &tx_queued_pri1);
	}

	// Save the current totals for nex time
	atomic64_set(&tx_ready_prev0, ready0);
	atomic64_set(&tx_ready_prev1, ready1);
	atomic64_add(ready0 + ready1, &tx_queued_t);

	// Copy over the current total to the next interval
	for (i = 0; i < NUM_STATS; ++i) {
		atomic64_set(&cb_event_stats.stats[next][i],
			     atomic64_read(&cb_event_stats.stats[curr][i]));
	}
	atomic_set(&current_stat, next);
	atomic_inc(&valid_stats);
	getnstimeofday(&cb_event_stats.time[next]);
	kernel_mem = hashtbl_get_memory();
	kernel_mem_peak = atomic64_read(&mem_kernel_peak);
	atomic64_set(&mem_kernel, kernel_mem);
	atomic64_set(&mem_kernel_peak,
		     (kernel_mem > kernel_mem_peak ? kernel_mem :
						     kernel_mem_peak));

	schedule_delayed_work(&stats_work, g_stats_work_delay);
}

// Print event stats
int cb_proc_show_events_avg(struct seq_file *m, void *v)
{
	// I add MAX_INTERVALS to some of the items below so that when I
	// subtract 1 it will
	//  still be a positive number.  The modulus math will clean it up
	//  later.
	uint32_t curr = atomic_read(&cb_event_stats.curr) + MAX_INTERVALS;
	uint32_t valid = atomic_read(&cb_event_stats.validStats);
	int32_t avg1_c = (valid > 4 ? 4 : valid);
	int32_t avg2_c = (valid > 20 ? 20 : valid);
	int32_t avg3_c = (valid > 60 ? 60 : valid);
	int32_t avg1 = (curr - avg1_c) % MAX_INTERVALS;
	int32_t avg2 = (curr - avg2_c) % MAX_INTERVALS;
	int32_t avg3 = (curr - avg3_c) % MAX_INTERVALS;

	int i;

	if (valid == 0) {
		seq_printf(m, "No Data\n");
		return 0;
	}

	// I only want to include valid intervals, so back the current pointer
	// to the last valid
	curr = (curr - 1) % MAX_INTERVALS;

	seq_printf(m, " %15s | %9s | %9s | %9s | %10s |\n", "Stat", "Total",
		   "1 min avg", "5 min avg", "15 min avg");

	// Uncomment this to debug the averaging
	// seq_printf(m, " %15s | %9d | %9d | %9d | %10d\n", "Avgs", curr, avg1,
	// avg2, avg3 );
	for (i = 1; i < EVENT_STATS; ++i) {
		// This is a circular array of elements were each element is an
		// increasing sum from the
		//  previous element. You can always get the sum of any two
		//  elements, and divide by the number of elements between them
		//  to yield the average.
		uint64_t currentStat =
			atomic64_read(&cb_event_stats.stats[curr][i]);
		seq_printf(m, " %15s | %9lld | %9lld | %9lld | %10lld |\n",
			   STAT_STRINGS[i].name, currentStat,
			   (currentStat -
			    atomic64_read(&cb_event_stats.stats[avg1][i])) /
				   avg1_c / STAT_INTERVAL,
			   (currentStat -
			    atomic64_read(&cb_event_stats.stats[avg2][i])) /
				   avg2_c / STAT_INTERVAL,
			   (currentStat -
			    atomic64_read(&cb_event_stats.stats[avg3][i])) /
				   avg3_c / STAT_INTERVAL);
	}

	seq_printf(m, "\n");

	return 0;
}

int cb_proc_show_events_det(struct seq_file *m, void *v)
{
	// I add MAX_INTERVALS to some of the items below so that when I
	// subtract 1 it will
	//  still be a positive number.  The modulus math will clean it up
	//  later.
	uint32_t curr = atomic_read(&cb_event_stats.curr);
	uint32_t valid = min(atomic_read(&cb_event_stats.validStats),
			     MAX_VALID_INTERVALS);
	uint32_t start =
		(MAX_INTERVALS + curr - valid) % MAX_INTERVALS + MAX_INTERVALS;
	int i;
	int j;

	if (valid == 0) {
		seq_printf(m, "No Data\n");
		return 0;
	}
	// seq_printf(m, "Curr = %d, valid = %d, start = %d\n", curr, valid,
	// start - MAX_INTERVALS );

	seq_printf(m, " %19s |", "Timestamp");
	for (j = 0; j < EVENT_STATS; ++j) {
		seq_printf(m, STAT_STRINGS[j].str_format, STAT_STRINGS[j].name);
	}
	seq_printf(m, "\n");

	for (i = 0; i < valid; ++i) {
		uint64_t left = (start + i - 1) % MAX_INTERVALS;
		uint64_t right = (start + i) % MAX_INTERVALS;

		seq_printf(m, " %19lld |",
			   to_windows_timestamp(&cb_event_stats.time[right]));
		for (j = 0; j < EVENT_STATS; ++j) {
			seq_printf(
				m, STAT_STRINGS[j].num_format,
				atomic64_read(&cb_event_stats.stats[right][j]) -
					atomic64_read(
						&cb_event_stats.stats[left][j]));
		}
		// seq_printf(m, " %9lld | %9lld |", left, right );
		seq_printf(m, "\n");
	}

	return 0;
}

ssize_t cb_proc_show_events_rst(struct file *file, const char *buf, size_t size,
				loff_t *ppos)
{
	int i;

	// Cancel the currently scheduled job
	cancel_delayed_work(&stats_work);

	// I do not need to zero out everything, just the new active interval
	atomic_set(&current_stat, 0);
	atomic_set(&valid_stats, 0);
	for (i = 0; i < NUM_STATS; ++i) {
		// We make sure the first and last interval are 0 for the
		// average calculations
		atomic64_set(&cb_event_stats.stats[0][i], 0);
		atomic64_set(&cb_event_stats.stats[MAX_INTERVALS - 1][i], 0);
	}
	getnstimeofday(&cb_event_stats.time[0]);

	// Resatrt the job from now
	schedule_delayed_work(&stats_work, g_stats_work_delay);
	return size;
}

int cb_proc_current_memory_avg(struct seq_file *m, void *v)
{
	// I add MAX_INTERVALS to some of the items below so that when I
	// subtract 1 it will
	//  still be a positive number.  The modulus math will clean it up
	//  later.
	uint32_t curr = atomic_read(&cb_event_stats.curr);

	int i;

	for (i = MEM_START; i < MEM_STATS; ++i) {
		// This is a circular array of elements were each element is an
		// increasing sum from the
		//  previous element. You can always get the sum of any two
		//  elements, and divide by the number of elements between them
		//  to yield the average.
		uint64_t currentStat =
			atomic64_read(&cb_event_stats.stats[curr][i]);
		seq_printf(m, "%9lld ", currentStat);
	}

	seq_printf(m, "\n");

	return 0;
}

int cb_proc_current_memory_det(struct seq_file *m, void *v)
{
	// I add MAX_INTERVALS to some of the items below so that when I
	// subtract 1 it will
	//  still be a positive number.  The modulus math will clean it up
	//  later.
	uint32_t curr = atomic_read(&cb_event_stats.curr);
	uint32_t valid = min(atomic_read(&cb_event_stats.validStats),
			     MAX_VALID_INTERVALS);
	uint32_t start =
		(MAX_INTERVALS + curr - valid) % MAX_INTERVALS + MAX_INTERVALS;
	int i;
	int j;

	if (valid == 0) {
		seq_printf(m, "No Data\n");
		return 0;
	}
	// seq_printf(m, "Curr = %d, valid = %d, start = %d\n", curr, valid,
	// start - MAX_INTERVALS );

	seq_printf(m, " %19s |", "Timestamp");
	for (j = MEM_START; j < MEM_STATS; ++j) {
		seq_printf(m, STAT_STRINGS[j].str_format, STAT_STRINGS[j].name);
	}
	seq_printf(m, "\n");

	for (i = 0; i < valid; ++i) {
		uint64_t right = (start + i) % MAX_INTERVALS;

		seq_printf(m, " %19lld |",
			   to_windows_timestamp(&cb_event_stats.time[right]));
		for (j = MEM_START; j < MEM_STATS; ++j) {
			seq_printf(
				m, STAT_STRINGS[j].num_format,
				atomic64_read(&cb_event_stats.stats[right][j]));
		}
		// seq_printf(m, " %9lld | %9lld |", left, right );
		seq_printf(m, "\n");
	}

	return 0;
}
