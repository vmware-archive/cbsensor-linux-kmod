/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

extern bool cbBanningInitialize(void);
extern void cbBanningShutdown(void);
extern void cbSetProtectionState(uint32_t new_mode);
extern bool cbSetBannedProcessInode(uint64_t ino);
extern inline bool cbClearBannedProcessInode(uint64_t ino);
extern bool cbKillBannedProcessByInode(uint64_t ino);
extern bool cbIngoreProcess(pid_t pid);
extern void cbSetIgnoredProcess(pid_t pid);
extern void cbClearIgnoredProcess(pid_t pid);
extern bool cbIngoreUid(pid_t uid);
extern void cbSetIgnoredUid(uid_t uid);
extern void cbClearAllBans(void);
