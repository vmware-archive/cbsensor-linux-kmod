/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

// This is a set of helper macros simplify all the nested if statements in code.

#include "dbg.h"

#define TRY(x) C_TEST(DEFAULT, (x), {}, {})
#define TRY_DO(x, stmt) C_TEST(DEFAULT, (x), {}, stmt)
#define TRY_DO_MSG(x, stmt, msg...) \
	C_TEST(                     \
		DEFAULT, (x), { PRINTK(msg); }, stmt)
#define TRY_MSG(x, msg...) C_TEST(DEFAULT, (x), { PRINTK(msg); }, {})
#define TRY_SET(x, val) C_TEST(DEFAULT, (x), { xcode = val; }, {})
#define TRY_SET_DO(x, val, stmt) \
	C_TEST(                  \
		DEFAULT, (x), { xcode = val; }, stmt)

#define TRY_STEP(step, x) C_TEST(step, (x), {}, {})
#define TRY_STEP_DO(step, x, stmt) C_TEST(step, (x), {}, stmt)

#define CANCEL_MSG(x, msg...) R_TEST((x), { PRINTK(msg); }, {})
#define CANCEL_VOID(x) R_TEST_V((x), {}, {})

#define C_TEST(step, x, stmt1, stmt2)                  \
	do {                                           \
		if (!(x)) {                            \
			stmt1 stmt2 goto CATCH_##step; \
		}                                      \
	} while (0)

#define R_TEST(x, stmt1, stmt2)                   \
	do {                                      \
		if (!(x)) {                       \
			stmt1 stmt2 return xcode; \
		}                                 \
	} while (0)

#define R_TEST_V(x, stmt1, stmt2)           \
	do {                                \
		if (!(x)) {                 \
			stmt1 stmt2 return; \
		}                           \
	} while (0)
