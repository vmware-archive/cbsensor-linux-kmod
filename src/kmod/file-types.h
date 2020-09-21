/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "../cbevent/src/CB_EVENT.h"
#include <linux/types.h>

#define MAX_FILE_BYTES_TO_DETERMINE_TYPE 68

void determine_file_type(char *buffer, uint32_t bytes_read,
			 enum CB_FILE_TYPE *pFileType, bool determineDataFiles);
char *file_type_str(enum CB_FILE_TYPE fileType);
