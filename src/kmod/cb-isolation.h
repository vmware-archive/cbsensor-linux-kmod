/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "../cbevent/src/CB_EVENT.h"
#include "../cbevent/src/CB_ISOLATION_MODE.h"
#include <linux/types.h>

enum CB_ISOLATION_ACTION {
	IsolationActionDisabled = 0,
	IsolationActionAllow = 1,
	IsolationActionBlock = 2
};

struct CB_ISOLATION_INTERCEPT_RESULT {
	enum CB_ISOLATION_ACTION isolationAction;
};

struct CB_ISOLATION_STATS {
	bool isolationEnabled;
	uint64_t isolationBlockedInboundIp4Packets;
	uint64_t isolationBlockedInboundIp6Packets;
	uint64_t isolationAllowedInboundIp4Packets;
	uint64_t isolationAllowedInboundIp6Packets;
};

int CbInitializeNetworkIsolation(void);

void CbDestroyNetworkIsolation(void);

int CbProcessIsolationSetMode(void *pBuf, uint32_t InputBufLen);

void CbIsolationInterceptByAddrProtoPort(
	uint32_t remoteIpAddress, bool isIpV4, uint32_t protocol, uint16_t port,
	struct CB_ISOLATION_INTERCEPT_RESULT *isolationResult);

extern struct CB_ISOLATION_STATS g_cbIsolationStats;
