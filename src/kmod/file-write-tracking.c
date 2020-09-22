/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define DS_MYSUBSYS DS_FILE
#include "file-write-tracking.h"
#include "file-write-cache.h"
#include "hash-table-generic.h"
#include "priv.h"

static struct HashTbl *file_write_table = NULL;

bool file_write_table_init(void)
{
	file_write_table = hashtbl_init_generic(
		BIT(15), sizeof(struct file_write_entry),
		sizeof(struct file_write_entry), "file_process_table",
		sizeof(struct file_write_key),
		offsetof(struct file_write_entry, key),
		offsetof(struct file_write_entry, link));
	if (!file_write_table) {
		return false;
	}
	fwc_register();
	return true;
}

void file_write_table_shutdown(void)
{
	if (file_write_table) {
		hashtbl_shutdown_generic(file_write_table);
		file_write_table = NULL;
		fwc_shutdown();
	}
}

bool is_file_tracked(struct file *file)
{
	struct file_write_entry *entry = NULL;
	struct file_write_key key = { .file = file };

	if (!file) {
		return false;
	}

	if (!file_write_table) {
		return false;
	}

	entry = hashtbl_get_generic(file_write_table, &key);
	if (!entry) {
		return false;
	}
	return true;
}

// Call When Brand New Entry
bool insert_file_entry(struct file *file, pid_t tgid)
{
	bool path_built;
	char *path_start = NULL;
	struct file_write_entry *entry = NULL;
	struct CB_EVENT *event = NULL;
	int add_ret = 0;
	bool ret = false;
	size_t offset;

	entry = hashtbl_alloc_generic(file_write_table, GFP_KERNEL);
	if (!entry) {
		return false;
	}
	memset(entry->path.buf, 0, sizeof(entry->path.buf));

	path_start = entry->path.buf;

	// By the time we get here another process or thread
	// may have closed the file handle.
	if (d_unlinked(file->f_path.dentry)) {
		goto out_free_entry;
	}

	path_built = file_get_path(file, entry->path.buf, &path_start);
	if (!path_built || !path_start || *path_start != '/') {
		goto out_free_entry;
	}
	offset = (&entry->path.buf[sizeof(entry->path.buf) - 1] - path_start);
	if (offset < sizeof(entry->path.buf)) {
		memmove(entry->path.buf, path_start, offset);
	} else {
		goto out_free_entry;
	}

	entry->last_tgid = tgid;
	entry->state.isSpecialFile =
		isSpecialFile(entry->path.buf, strlen(entry->path.buf));
	entry->key.file = file;
	entry->state.fileType = filetypeUnknown;
	entry->state.didReadType = false;
	entry->state.try_vfs_read = true;
	if (entry->state.isSpecialFile) {
		entry->state.try_vfs_read = false;
	}

	event = logger_alloc_event(CB_EVENT_TYPE_FILE_WRITE, current);
	if (!event) {
		goto out_free_entry;
	}

	event->fileGeneric.file_type = entry->state.fileType;
	memcpy(event->fileGeneric.path, entry->path.buf, PATH_MAX);

	// Another thread beat us to inserting entry
	add_ret = hashtbl_add_safe_generic(file_write_table, entry);
	if (add_ret == -EEXIST) {
		logger_free_event_on_error(event);
		event = NULL;
		goto out_free_entry;
	}
	logger_submit_event(event);
	ret = true;

	return ret;

out_free_entry:
	if (entry) {
		hashtbl_free_generic(file_write_table, entry);
		entry = NULL;
	}
	return ret;
}

// Call When File Entry Already Exists
// but new tgid using same file handle.
// Common for forked or execs reusing file descriptors.
bool update_file_entry(struct file *file, pid_t tgid)
{
	bool found;
	struct CB_EVENT *event = NULL;
	struct file_type_state state;

	event = logger_alloc_event_notask(CB_EVENT_TYPE_FILE_WRITE, tgid,
					  GFP_KERNEL);
	if (!event) {
		return false;
	}

	// Updates last_tgid and fills in filepath for log event
	found = update_tgid_entry_data(file, tgid, &state,
				       event->fileGeneric.path);
	// If not found or tgid changed on us and matches.
	if (!found) {
		logger_free_event_on_error(event);
		return false;
	}

	event->fileGeneric.file_type = state.fileType;
	logger_submit_event(event);
	return true;
}

// No need for getting a safe copy
// Not a great place for determining which "task" this is
bool remove_file_entry(struct file *file)
{
	struct CB_EVENT *event = NULL;
	struct file_write_entry *entry = NULL;
	bool ret = false;
	struct file_write_key key = { .file = file };

	if (!should_log(CB_EVENT_TYPE_FILE_CLOSE)) {
		entry = hashtbl_del_by_key_generic(file_write_table, &key);
		if (entry) {
			hashtbl_free_generic(file_write_table, entry);
			entry = NULL;
			ret = true;
		}
		return ret;
	}

	entry = hashtbl_del_by_key_generic(file_write_table, &key);
	if (!entry) {
		return true;
	}

	if (entry->state.isSpecialFile) {
		hashtbl_free_generic(file_write_table, entry);
		return true;
	}

	event = logger_alloc_event_notask(CB_EVENT_TYPE_FILE_CLOSE,
					  entry->last_tgid, GFP_KERNEL);
	if (!event) {
		hashtbl_free_generic(file_write_table, entry);
		return false;
	}

	event->fileGeneric.file_type = entry->state.fileType;
	memcpy(event->fileGeneric.path, entry->path.buf, PATH_MAX);
	logger_submit_event(event);
	ret = true;

	hashtbl_free_generic(file_write_table, entry);

	return ret;
}

bool set_file_entry_data(struct file *file, pid_t *last_tgid,
			 struct file_type_state *state, const char *path)
{
	bool found;
	struct hashtbl_bkt *bkt = NULL;
	unsigned long flags = 0;
	struct file_write_entry *entry = NULL;
	struct file_write_key key = { .file = file };
	if (!file || (!path && !state && !last_tgid)) {
		return false;
	}

	// lock bucket
	found = hashtbl_getlocked_bucket(file_write_table, &key,
					 (void **)&entry, &bkt, &flags);
	if (found) {
		if (entry) {
			if (last_tgid) {
				entry->last_tgid = *last_tgid;
			}
			if (state) {
				memcpy(&entry->state, state, sizeof(*state));
			}
			if (path) {
				strncpy(entry->path.buf, path, PATH_MAX);
			}
		}
		if (bkt) {
			hashtbl_unlock_bucket(bkt, flags);
		}
	}

	return found;
}

bool get_file_entry_data(struct file *file, pid_t *last_tgid,
			 struct file_type_state *state,
			 struct file_write_path *path)
{
	bool found;
	struct hashtbl_bkt *bkt = NULL;
	unsigned long flags = 0;
	struct file_write_entry *entry = NULL;
	struct file_write_key key = { .file = file };

	if (!file || (!state && !path && !last_tgid)) {
		return false;
	}

	// lock bucket
	found = hashtbl_getlocked_bucket(file_write_table, &key,
					 (void **)&entry, &bkt, &flags);
	if (found) {
		if (entry) {
			if (last_tgid) {
				*last_tgid = entry->last_tgid;
			}
			if (state) {
				memcpy(state, &entry->state, sizeof(*state));
			}
			if (path) {
				memcpy(path, &entry->path, sizeof(*path));
			}
		}
		if (bkt) {
			hashtbl_unlock_bucket(bkt, flags);
		}
	}
	return found;
}

bool update_tgid_entry_data(struct file *file, pid_t last_tgid,
			    struct file_type_state *state, char *path)
{
	bool found;
	struct hashtbl_bkt *bkt = NULL;
	unsigned long flags = 0;
	struct file_write_entry *entry = NULL;
	struct file_write_key key = { .file = file };

	if (!file || !last_tgid || (!state && !path)) {
		return false;
	}

	// lock bucket
	found = hashtbl_getlocked_bucket(file_write_table, &key,
					 (void **)&entry, &bkt, &flags);
	if (found) {
		if (entry) {
			// If we match someone else already changed it
			// preventing a racing duplicate
			if (entry->last_tgid == last_tgid) {
				found = false;
			} else {
				entry->last_tgid = last_tgid;
			}
			// Copy State and Filepath Back
			if (state) {
				memcpy(state, &entry->state, sizeof(*state));
			}
			if (path) {
				memcpy(path, entry->path.buf, PATH_MAX);
			}
		}
		if (bkt) {
			hashtbl_unlock_bucket(bkt, flags);
		}
	}
	return found;
}

static char *getTypeStr(enum CB_FILE_TYPE type)
{
	char *str = "unknown";

	switch (type) {
	case filetypePe:
		str = "PE";
		break;
	case filetypeElf:
		str = "ELF";
		break;
	case filetypeUniversalBin:
		str = "Univ. Bin";
		break;
	case filetypeEicar:
		str = "EICAR";
		break;
	case filetypeOfficeLegacy:
		str = "Office Legacy";
		break;
	case filetypeOfficeOpenXml:
		str = "Office Open XML";
		break;
	case filetypePdf:
		str = "PDF";
		break;
	case filetypeArchivePkzip:
		str = "PKZIP";
		break;
	case filetypeArchiveLzh:
		str = "LZH";
		break;
	case filetypeArchiveLzw:
		str = "LZW";
		break;
	case filetypeArchiveRar:
		str = "RAR";
		break;
	case filetypeArchiveTar:
		str = "TAR";
		break;
	case filetypeArchive7zip:
		str = "7 ZIP";
		break;
	case filetypeUnknown:
	default:
		break;
	}
	return str;
}

static int _show_file_tracking_table(struct HashTbl *hashTblp,
				     struct HashTableNode *nodep, void *priv)
{
	struct file_write_entry *entry = (struct file_write_entry *)nodep;
	struct seq_file *m = (struct seq_file *)priv;

	seq_printf(m, "%40s | %#18llx | %6llu | %10s | %15s |\n",
		   entry->path.buf, (uint64_t)entry->key.file,
		   (uint64_t)entry->last_tgid,
		   (entry->state.isSpecialFile ? "YES" : "NO"),
		   getTypeStr(entry->state.fileType));

	return ACTION_CONTINUE;
}

int cb_file_track_show_table(struct seq_file *m, void *v)
{
	seq_printf(m, "%40s | %18s | %6s | %11s | %15s |\n", "Path", "Inode",
		   "PID", "Is Special", "Type");
	hashtbl_for_each_generic(file_write_table, _show_file_tracking_table,
				 m);
	return 0;
}
