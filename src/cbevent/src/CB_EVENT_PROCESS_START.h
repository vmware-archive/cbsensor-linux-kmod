/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#else
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#endif

#include <linux/limits.h>

#include "CB_CMDLINE.h"

#define CB_PROCESS_START_BY_FORK 0x00000001
#define CB_PROCESS_START_BY_EXEC 0x00000002

#pragma pack(push, 1)
struct CB_EVENT_PROCESS_START {
	pid_t parent;
	uid_t uid;
	int start_action; // 1 = FORK 2 = EXEC
	bool observed; // Flag to identify if the start was actually observed,
		// or this fake
	uint64_t inode; // If we have it otherwise 0
	char path[PATH_MAX + 1];
	cb_cmdline_t cmdLine;
	bool path_found;
};
#pragma pack(pop)
