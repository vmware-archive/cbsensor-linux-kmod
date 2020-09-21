/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#include <linux/in.h>
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif

union CB_SOCK_ADDR {
	struct sockaddr_storage ss_addr;
	struct sockaddr sa_addr;
	struct sockaddr_in as_in4;
	struct sockaddr_in6 as_in6;
};
