/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

enum CB_ISOLATION_MODE { IsolationModeOff = 0, IsolationModeOn = 1 };

struct CB_ISOLATION_MODE_CONTROL {
	enum CB_ISOLATION_MODE isolationMode;
	uint32_t numberOfAllowedIpAddresses;
	uint32_t allowedIpAddresses[1];
};
