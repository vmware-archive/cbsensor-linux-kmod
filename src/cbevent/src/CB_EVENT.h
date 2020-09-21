/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include "CB_EVENT_BLOCK_RESPONSE.h"
#include "CB_EVENT_DNS_RESPONSE.h"
#include "CB_EVENT_FILE_GENERIC.h"
#include "CB_EVENT_HEARTBEAT.h"
#include "CB_EVENT_MODULE_LOAD.h"
#include "CB_EVENT_NETWORK_CONNECT.h"
#include "CB_EVENT_PROCESS_EXIT.h"
#include "CB_EVENT_PROCESS_INFO.h"
#include "CB_EVENT_PROCESS_START.h"
#include "CB_EVENT_TYPE.h"

#pragma pack(push, 1)
struct CB_EVENT {
	enum CB_EVENT_TYPE eventType;
	struct CB_EVENT_PROCESS_INFO procInfo;

	union {
		struct CB_EVENT_PROCESS_START processStart;
		struct CB_EVENT_PROCESS_EXIT processExit;
		struct CB_EVENT_MODULE_LOAD moduleLoad;

		struct CB_EVENT_FILE_GENERIC fileGeneric;
		struct CB_EVENT_FILE_GENERIC fileCreate;
		struct CB_EVENT_FILE_GENERIC fileDelete;

		struct CB_EVENT_NETWORK_CONNECT netConnect;
		struct CB_EVENT_DNS_RESPONSE dnsResponse;
		struct CB_EVENT_BLOCK blockResponse;
		struct CB_EVENT_HEARTBEAT heartbeat;
	};

	unsigned long canary;
};
#pragma pack(pop)
