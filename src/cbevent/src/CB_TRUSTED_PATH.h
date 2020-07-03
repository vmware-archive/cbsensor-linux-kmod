/*
 * Copyright 2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#else
#include <limits.h>
#endif

struct CB_TRUSTED_PATH {
	char path[PATH_MAX + 1];
};
