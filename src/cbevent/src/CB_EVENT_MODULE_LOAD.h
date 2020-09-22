/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include <linux/limits.h>

#pragma pack(push, 1)
struct CB_EVENT_MODULE_LOAD {
	char moduleName[PATH_MAX + 1];
	int64_t baseaddress;
};
#pragma pack(pop)
