/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t ques_num;
	uint16_t ans_num;
	uint16_t auth_rrs;
	uint16_t addi_rrs;
};

#pragma pack(push, 1)
struct CB_EVENT_DNS_RESPONSE {
	uint32_t length;
	union {
		struct dnshdr dnsheader;
		unsigned char data[768];
	};
};
#pragma pack(pop)
