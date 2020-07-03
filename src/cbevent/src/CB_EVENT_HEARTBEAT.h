/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>

#pragma pack(push, 1)
struct CB_EVENT_HEARTBEAT {
	size_t user_memory;
	size_t user_memory_peak;
	size_t kernel_memory;
	size_t kernel_memory_peak;
};
#pragma pack(pop)
