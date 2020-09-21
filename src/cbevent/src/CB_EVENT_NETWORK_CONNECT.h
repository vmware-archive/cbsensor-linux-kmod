/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/socket.h>
#endif

#include "CB_SOCK_ADDR.h"

#define CB_PROXY_SERVER_MAX_LEN 256

#pragma pack(push, 1)
struct CB_EVENT_NETWORK_CONNECT {
	int32_t protocol;
	union CB_SOCK_ADDR localAddr;
	union CB_SOCK_ADDR remoteAddr;
	char actual_server[CB_PROXY_SERVER_MAX_LEN];
	uint16_t actual_port;

#ifdef __cplusplus
	bool is_v4() const
	{
		return localAddr.ss_addr.ss_family == AF_INET;
	}
#endif
};
#pragma pack(pop)
