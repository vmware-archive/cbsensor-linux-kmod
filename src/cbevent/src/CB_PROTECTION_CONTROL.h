/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#pragma pack(push, 1)

struct protectionData {
	int action;
	uint64_t inode;
};

#define KERNMSG_MAX 10
struct CB_PROTECTION_CONTROL {
	uint64_t count; // 1 - 10
	struct protectionData data[KERNMSG_MAX];
};

#pragma pack(pop)
