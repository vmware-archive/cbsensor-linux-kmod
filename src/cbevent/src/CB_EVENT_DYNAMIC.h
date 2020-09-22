/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#else
#include <stddef.h>
#endif

struct CB_EVENT_DYNAMIC {
	size_t size;
	unsigned long data;
};
