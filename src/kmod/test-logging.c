/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "dbg.h"
#include <linux/kernel.h>

void test_logging(void)
{
	PRINTK(KERN_ERR, "ERROR messages enabled");
	PRINTK(KERN_WARNING, "WARNING messages enabled");
	PRINTK(KERN_INFO, "INFO messages enabled");

	/* Messages will be printed for only the enabled subsystems.
	 */
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_COMMS
	PR_DEBUG("COMMS messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_FILE
	PR_DEBUG("FILE messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_HASH
	PR_DEBUG("HASH messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_BAN
	PR_DEBUG("BAN messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_HOOK
	PR_DEBUG("HOOK messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_ISOLATE
	PR_DEBUG("ISOLATE messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_LOG
	PR_DEBUG("LOG messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_LSM
	PR_DEBUG("LSM messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_MOD
	PR_DEBUG("MOD messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_NET
	PR_DEBUG("NET messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_PROC
	PR_DEBUG("PROC messages enabled");
#undef DS_MYSUBSYS
#define DS_MYSUBSYS DS_PROCFS
	PR_DEBUG("PROCFS messages enabled");
#undef DS_MYSUBSYS
}
