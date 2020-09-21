/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once
//
// ktfutce handles a queue of Fork events and the tgid in question.
// We may want to pre-allocate a process tracking table entry and
// send to here as well and fill in all the data.
//
// With our current fork hook we cannot safely lookup the new
// task yet. So we throw the job into our kthread via a
// wait queue. By the time this thread wakes the new task
// will highly likely be available.
//
int ktfutce_register(void);
void ktfutce_shutdown(void);

int ktfutce_add_pid(pid_t pid, struct CB_EVENT *event, gfp_t mode);
