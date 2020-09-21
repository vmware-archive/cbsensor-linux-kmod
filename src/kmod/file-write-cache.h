/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <linux/slab.h>
#include <linux/types.h>

int fwc_register(void);
void fwc_shutdown(void);
int fwc_entry_exists(pid_t tgid, ino_t inode, dev_t dev, u64 time, gfp_t mode);
