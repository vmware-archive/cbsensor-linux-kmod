/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#define CB_MAX_CMDLINE_SIZE 1024

#pragma pack(push, 1)
typedef struct _cb_cmdline {
	char v[CB_MAX_CMDLINE_SIZE + 1];
} cb_cmdline_t;
#pragma pack(pop)
