/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "hash-table-generic.h"
#include "priv.h"

struct file_type_state {
	enum CB_FILE_TYPE fileType;
	bool didReadType;
	bool isSpecialFile;
	bool try_vfs_read;
};
struct file_write_path {
	char buf[PATH_MAX + 1];
};

struct file_write_key {
	struct file *file;
};
// Add inode and device when CB_EVENT
// can handle them on generic file events
struct file_write_entry {
	struct HashTableNode link;
	struct file_write_key key;
	pid_t last_tgid;
	struct file_type_state state;
	struct file_write_path path;
};

bool file_write_table_init(void);
void file_write_table_shutdown(void);
bool is_file_tracked(struct file *file);
bool insert_file_entry(struct file *file, pid_t tgid);
bool update_file_entry(struct file *file, pid_t tgid);
bool remove_file_entry(struct file *file);
bool set_file_entry_data(struct file *file, pid_t *last_tgid,
			 struct file_type_state *state, const char *path);
bool get_file_entry_data(struct file *file, pid_t *last_tgid,
			 struct file_type_state *state,
			 struct file_write_path *path);
bool update_tgid_entry_data(struct file *file, pid_t last_tgid,
			    struct file_type_state *state, char *path);
