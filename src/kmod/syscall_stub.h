/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#define CBSYSSTUB_NAME(c_name) cbstub_sys_##c_name
#define ORIG_SYSCALL_PTR(c_name) orig_syscall_##c_name##_ptr
