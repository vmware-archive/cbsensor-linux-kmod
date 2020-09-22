/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/types.h>
#endif
#include <linux/limits.h>

#include "CB_CMDLINE.h"

enum ProcessBlockType {
	BlockDuringProcessStartup, ///< We killed (or tried to kill) the process
	///< when its initial thread was being
	///< created
	ProcessTerminatedAfterStartup ///< We killed (or tried to kill) the
	///< process after the process was running
};

/// @brief When we fail to terminate a process, we generate an event to the
/// server telling it why we couldn't
///   These enums help inform the server as to why
enum TerminateFailureReason {
	TerminateFailureReasonNone = 0, ///< Process was successfully terminated
	ProcessOpenFailure = 2, ///< We failed to open a handle to the process
	///< (failure details will contain NT_STATUS
	///< error code)
	ProcessTerminateFailure, ///< ZwTerminateProcess failed (failure details
	///< will contain NT_STATUS error code)
};

#pragma pack(push, 1)
struct CB_EVENT_BLOCK {
	enum ProcessBlockType blockType;
	enum TerminateFailureReason failureReason;
	uint32_t failureReasonDetails;
	uid_t uid;
	uint64_t inode; // If we have it otherwise 0
	char path[PATH_MAX + 1];
	cb_cmdline_t cmdLine;
	bool path_found;
};
#pragma pack(pop)
