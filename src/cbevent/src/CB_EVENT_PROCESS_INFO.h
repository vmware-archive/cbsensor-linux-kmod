/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#include <linux/time.h>
#else
#include <sys/types.h>
#include <time.h>
#endif

#pragma pack(push, 1)
struct CB_EVENT_PROCESS_INFO {
	pid_t pid; // Process id for this event
	time_t process_start_time; // Windows time the process at 'pid' started
	time_t event_time; // Windows time this event occurred
	struct timespec process_start_time_unix; // Unix time that the process
		// at 'pid' started
	struct timespec event_time_unix; // Unix time that this event occurred
};
#pragma pack(pop)
