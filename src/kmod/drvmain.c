/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cb-isolation.h"
#include "file-write-tracking.h"
#include "ktfutce.h"
#include "network-tracking.h"
#include "priv.h"
#include "process-tracking.h"
#include "version.h"

#include "../cbevent/src/CB_EVENT_FILTER.h"

#ifdef HOOK_SELECTOR
#define HOOK_MASK 0x00000000
#else
#define HOOK_MASK 0xFFFFFFFF
#endif

uint32_t g_debug_subsystem = 0;
uint32_t g_eventFilter = CB_EVENT_FILTER_ALL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
uint32_t g_pid_gc_freq = 0;
#else
uint32_t g_pid_gc_freq = 30;
#endif
uint32_t g_enableHooks = HOOK_MASK;
uid_t g_cb_server_uid = (uid_t)-1;
int64_t g_cb_ignored_pid_count = 0;
pid_t g_cb_ignored_pids[CB_SENSOR_MAX_PIDS];
int64_t g_cb_ignored_uid_count = 0;
uid_t g_cb_ignored_uids[CB_SENSOR_MAX_UIDS];
bool g_exiting = false;

module_param(g_debug_subsystem, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(g_eventFilter, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(g_pid_gc_freq, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
#ifdef HOOK_SELECTOR
module_param(g_enableHooks, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
#endif

INIT_CB_RESOLVED_SYMS();
atomic64_t module_used = ATOMIC64_INIT(0);

static int __init cbsensor_init(void)
{
#undef CB_RESOLV_VARIABLE
#undef CB_RESOLV_FUNCTION
#define CB_RESOLV_VARIABLE(V_TYPE, V_NAME) \
	{ #V_NAME, strlen(#V_NAME),        \
	  (unsigned long *)&g_resolvedSymbols.V_NAME },
#define CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL) \
	CB_RESOLV_VARIABLE(F_TYPE, F_NAME)

	struct symbols_s symbols[] = { CB_RESOLV_SYMBOLS{ NULL, 0, NULL } };
	struct symbol_list sym_list = {
		.symbols = symbols,
		.size = ARRAY_SIZE(symbols) - 1, // Prevent extra iterations
		.count = 0,
	};

	PRINT_VERSION_INFO;

	// Issue print statements to show which logging levels and subsystems
	// are enabled if DS_TEST is specified.
	if (g_debug_subsystem | DS_TEST) {
		test_logging();
	}

	//
	// Initialize Subsystems
	//
	memset(&g_cb_ignored_pids[0], 0, sizeof(pid_t) * CB_SENSOR_MAX_PIDS);
	memset(&g_cb_ignored_uids[0], 0xFF, sizeof(uid_t) * CB_SENSOR_MAX_PIDS);

	// Actually do the lookup
	lookup_symbols(&sym_list);

	TRY(process_tracking_initialize());
	TRY_STEP(PROC, network_tracking_initialize());
	TRY_STEP(NET_TR, cbBanningInitialize());
	TRY_STEP(BAN, !CbInitializeNetworkIsolation());
	TRY_STEP(NET_IS, file_helper_init());
	TRY_STEP(NET_IS, logger_initialize());
	ktfutce_register();
	TRY_STEP(TASK, netfilter_initialize(g_enableHooks));
	TRY_STEP(NET_FIL, file_write_table_init());
	TRY_STEP(FILE_PROC, lsm_initialize(g_enableHooks));
	TRY_STEP(LSM, syscall_initialize(g_enableHooks));
	TRY_STEP(SYSCALL, cb_proc_initialize());
	TRY_STEP(DEVNODE, user_devnode_init());

	PRINTK(KERN_INFO, "Kernel sensor initialization complete");
	return 0; // Non-zero return means that the module couldn't be loaded.

CATCH_DEVNODE:
	cb_proc_shutdown();
CATCH_SYSCALL:
	syscall_shutdown(g_enableHooks);
CATCH_LSM:
	lsm_shutdown();
CATCH_FILE_PROC:
	file_write_table_shutdown();
CATCH_NET_FIL:
	netfilter_cleanup(g_enableHooks);
CATCH_TASK:
	ktfutce_shutdown();
	logger_shutdown();
CATCH_NET_IS:
	CbDestroyNetworkIsolation();
CATCH_BAN:
	cbBanningShutdown();
CATCH_NET_TR:
	network_tracking_shutdown();
CATCH_PROC:
	process_tracking_shutdown();
CATCH_DEFAULT:
	PRINTK(KERN_ERR, "Kernel sensor initialization failed");
	return -1;
}

void cbsensor_shutdown(void)
{
	// If the hooks have been modified abort the shutdown.
	if (syscall_hooks_changed(g_enableHooks) ||
	    lsm_hooks_changed(g_enableHooks)) {
		PRINTK(KERN_WARNING,
		       "System call hooks changed, not removing hooks");
		return;
	}

	// Remove hooks
	cb_proc_shutdown();
	syscall_shutdown(g_enableHooks);
	lsm_shutdown();
	netfilter_cleanup(g_enableHooks);
	ktfutce_shutdown();
}

static void __exit cbsensor_cleanup(void)
{
	uint64_t l_module_used;
	PRINTK(KERN_INFO, "Cleaning up module...");

	// I want to globally notify that we are exiting, but not until the
	// hooks have been removed
	g_exiting = true;

	// We have to be sure we're not in a hook. Wait here until nothing is
	// using our module. NOTE: We only care about the actual hooks.  If our
	// dev node is open, Linux will already
	//  prevent unloading.
	while ((l_module_used = atomic64_read(&module_used)) != 0) {
		PRINTK(KERN_INFO,
		       "Module has %lld active hooks, delaying shutdown...",
		       l_module_used);
		ssleep(5);
	}

	file_write_table_shutdown();
	logger_shutdown();
	ssleep(2); // @@TODO: we have to be sure we're not in a hook. need two
		// phase driver. very tricky
	CbDestroyNetworkIsolation();
	cbBanningShutdown();
	network_tracking_shutdown();
	process_tracking_shutdown();

	PRINTK(KERN_INFO, "Cbsensor driver cleanup complete.");
}

module_init(cbsensor_init);
module_exit(cbsensor_cleanup);

MODULE_LICENSE("GPL v2");
