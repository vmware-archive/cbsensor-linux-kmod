/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#else
#include <sys/types.h>
#endif

#pragma pack(push, 1)
struct CB_EVENT_PROCESS_EXIT {
	pid_t pid;
};
#pragma pack(pop)
