/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "CB_FILE_TYPE.h"
#include <linux/limits.h>

#pragma pack(push, 1)
struct CB_EVENT_FILE_GENERIC {
	char path[PATH_MAX + 1];
	enum CB_FILE_TYPE file_type;
};
#pragma pack(pop)
