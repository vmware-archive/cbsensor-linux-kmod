/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
#include <linux/string.h>

// Debug message subsystems.
#define DS_COMMS 0x0002
#define DS_FILE 0x0004
#define DS_HASH 0x0008
#define DS_BAN 0x0010
#define DS_HOOK 0x0020
#define DS_ISOLATE 0x0040
#define DS_LOG 0x0080
#define DS_LSM 0x0100
#define DS_MOD 0x0200
#define DS_NET 0x0400
#define DS_PROC 0x0800
#define DS_PROCFS 0x1000
#define DS_TEST 0x8000
#define DS_MASK 0xFFFF

#define __SHORT_FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define PRINTK(level, fmt, ...)                                             \
	printk(level "cbsensor: %s:%d: " fmt, __SHORT_FILENAME__, __LINE__, \
	       ##__VA_ARGS__)

#define PRINTK_RATELIMITED(level, fmt, ...)                                   \
	printk_ratelimited(level "cbsensor: %s:%d: " fmt, __SHORT_FILENAME__, \
			   __LINE__, ##__VA_ARGS__)

extern uint32_t g_debug_subsystem;

void test_logging(void);

#define DS_ENABLED(flag) ((flag & DS_MASK) & g_debug_subsystem)

#ifndef DS_MYSUBSYS
#define DS_MYSUBSYS 0
#endif

#define PR_DEBUG(fmt, ...)                                            \
	if (DS_ENABLED(DS_MYSUBSYS))                                  \
	pr_info("cbsensor: %s:%d: " fmt, __SHORT_FILENAME__,          \
	       __LINE__, ##__VA_ARGS__)

#define PR_DEBUG_RATELIMITED(fmt, ...)                        \
	if (DS_ENABLED(DS_MYSUBSYS))                          \
	pr_info_ratelimited("cbsensor: %s:%d: " fmt,          \
			   __SHORT_FILENAME__, __LINE__, ##__VA_ARGS__)
