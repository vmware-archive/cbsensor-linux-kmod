/*
 * Copyright 2019-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

// This is a set of helper macros simplify all the nested if statements in code.

#include "dbg.h"

#define TRY(x)                              \
	do {                                \
		if (!(x)) {                 \
			goto CATCH_DEFAULT; \
		}                           \
	} while (0)

#define TRY_DO(x, stmt)                     \
	do {                                \
		if (!(x)) {                 \
			stmt;               \
			goto CATCH_DEFAULT; \
		}                           \
	} while (0)

#define TRY_DO_MSG(x, stmt, msg...)         \
	do {                                \
		if (!(x)) {                 \
			PRINTK(msg);        \
			stmt;               \
			goto CATCH_DEFAULT; \
		}                           \
	} while (0)

#define TRY_MSG(x, msg...)                  \
	do {                                \
		if (!(x)) {                 \
			PRINTK(msg);        \
			goto CATCH_DEFAULT; \
		}                           \
	} while (0)

#define TRY_SET(x, val)                     \
	do {                                \
		if (!(x)) {                 \
			xcode = val;        \
			goto CATCH_DEFAULT; \
		}                           \
	} while (0)

#define TRY_SET_DO(x, val, stmt)            \
	do {                                \
		if (!(x)) {                 \
			xcode = val;        \
			stmt;               \
			goto CATCH_DEFAULT; \
		}                           \
	} while (0)

#define TRY_STEP(step, x)                  \
	do {                               \
		if (!(x)) {                \
			goto CATCH_##step; \
		}                          \
	} while (0)

#define TRY_STEP_DO(step, x, stmt)         \
	do {                               \
		if (!(x)) {                \
			stmt;              \
			goto CATCH_##step; \
		}                          \
	} while (0)
