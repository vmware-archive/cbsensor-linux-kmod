/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include "priv.h"
#include <linux/types.h>

struct FILE_PROCESS_VALUE {
	bool		  hasBeenWritten;
	enum CB_FILE_TYPE fileType;
	bool		  didReadType;
	bool		  isSpecialFile;
	bool		  try_vfs_read;
	char		  buffer[PATH_MAX + 1];
	char *		  path;
};

extern uint64_t		  g_file_list_lock;
extern struct list_head	  g_lost_file_list;
extern struct work_struct g_file_track_work;

bool			   file_process_tracking_init(void);
void			   file_process_tracking_shutdown(void);
struct FILE_PROCESS_VALUE *file_process_status(uint64_t inode, dev_t dev,
					       uint32_t pid);
struct FILE_PROCESS_VALUE *file_process_status_open(uint64_t inode, dev_t dev,
						    uint32_t pid);
void file_process_status_close(uint64_t inode, dev_t dev, uint32_t pid);
void check_open_file_list_on_exit(struct list_head *file_list);
bool check_open_file_list_on_exit_lock(struct list_head *file_list);
