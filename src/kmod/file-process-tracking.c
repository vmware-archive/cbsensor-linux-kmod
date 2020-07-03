/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS DS_FILE
#include "file-process-tracking.h"
#include "hash-table-generic.h"
#include "priv.h"
#include "process-tracking.h"

struct table_key {
	uint64_t inode;
	dev_t	 dev;
	uint32_t pid;
};

struct table_element {
	struct HashTableNode	  link;
	struct table_key	  key;
	struct FILE_PROCESS_VALUE value;
	// The process tracking logic now keeps a list of all the open files
	struct list_head siblings;
};

struct HashTbl *hash_table;
uint64_t	g_file_list_lock = 0;
// On process exit, we move any unclosed files to this list and clean them up
// later
LIST_HEAD(g_lost_file_list);

#define FILE_PROCESS_OBJ_SIZE 64
bool file_process_tracking_init()
{
	cb_initspinlock(&g_file_list_lock);
	hash_table = hashtbl_init_generic(8192, sizeof(struct table_element),
					  FILE_PROCESS_OBJ_SIZE,
					  "file_process_table",
					  sizeof(struct table_key),
					  offsetof(struct table_element, key),
					  offsetof(struct table_element, link));

	if (!hash_table) {
		PRINTK(KERN_ERR, "failed to allocate file process hash table");
		return false;
	}

	return true;
}

void file_process_tracking_shutdown()
{
	hashtbl_shutdown_generic(hash_table);
	cb_destroyspinlock(&g_file_list_lock);
	g_file_list_lock = 0;
}

struct FILE_PROCESS_VALUE *file_process_status_open(uint64_t inode, dev_t dev,
						    uint32_t pid)
{
	struct table_key	   key;
	struct table_element *	   data_ptr;
	struct FILE_PROCESS_VALUE *value = NULL;
	struct list_head *	   files;

	key.inode = inode;
	key.dev	  = dev;
	key.pid	  = pid;

	data_ptr = (struct table_element *)hashtbl_alloc_generic(hash_table,
								 GFP_KERNEL);
	TRY_STEP(NO_LOCK, data_ptr);

	data_ptr->key.inode	       = inode;
	data_ptr->key.dev	       = dev;
	data_ptr->key.pid	       = pid;
	data_ptr->value.hasBeenWritten = true;
	data_ptr->value.isSpecialFile  = false;
	data_ptr->value.path	       = data_ptr->value.buffer;
	data_ptr->value.fileType       = filetypeUnknown;
	data_ptr->value.didReadType    = false;
	data_ptr->value.try_vfs_read   = true;
	INIT_LIST_HEAD(&(data_ptr->siblings));

	// Only take the spin lock now that I am starting to manipulate the
	// list.  Be aware
	//  that there is a GFP_KERNEL memory allocation above if this ever is
	//  moved.
	cb_spinlock(&g_file_list_lock);
	TRY_DO(hashtbl_add_generic(hash_table, data_ptr) == 0, {
		hashtbl_free_generic(hash_table, data_ptr);
		PRINTK(KERN_ERR,
		       "Fail to add inode:%llu pid:%u into file_process hash table",
		       inode, pid);
	});

	// We need to ask the process tracking logic which list to add this file
	// to
	files = process_tracking_get_file_list(pid);
	if (likely(files)) {
		list_add(&(data_ptr->siblings), files);
	}
	// This should never happen, but just in case
	else {
		PR_DEBUG("Adding file for untracked pid %u", pid);
	}

	value = &data_ptr->value;

CATCH_DEFAULT:
	cb_spinunlock(&g_file_list_lock);

CATCH_NO_LOCK:
	return value;
}

struct FILE_PROCESS_VALUE *file_process_status(uint64_t inode, dev_t dev,
					       uint32_t pid)
{
	struct table_key	   key;
	struct table_element *	   data_ptr;
	struct FILE_PROCESS_VALUE *value = NULL;
	cb_spinlock(&g_file_list_lock);

	key.inode = inode;
	key.dev	  = dev;
	key.pid	  = pid;
	data_ptr  = hashtbl_get_generic(hash_table, &key);

	if (data_ptr != NULL) {
		value = &data_ptr->value;
	}

	cb_spinunlock(&g_file_list_lock);

	return value;
}

void file_process_status_close(uint64_t inode, dev_t dev, uint32_t pid)
{
	struct table_key      key;
	struct table_element *data_ptr;
	cb_spinlock(&g_file_list_lock);

	key.inode = inode;
	key.dev	  = dev;
	key.pid	  = pid;

	data_ptr = hashtbl_del_by_key_generic(hash_table, &key);
	if (data_ptr != NULL) {
		list_del(&(data_ptr->siblings));
		hashtbl_free_generic(hash_table, data_ptr);
	} else {
		PRINTK(KERN_ERR,
		       "Fail to delete inode=%llu, pid=%u from hash table",
		       inode, pid);
	}
	cb_spinunlock(&g_file_list_lock);
}

// Loop over the lost file list, to clean it up
static void cleanup_lost_files(struct work_struct *work)
{
	struct table_element *data_ptr;
	struct table_element *tmp;

	cb_spinlock(&g_file_list_lock);
	list_for_each_entry_safe (data_ptr, tmp, &g_lost_file_list, siblings) {
		list_del(&(data_ptr->siblings));
		hashtbl_del_generic(hash_table, data_ptr);
		hashtbl_free_generic(hash_table, data_ptr);
	}
	cb_spinunlock(&g_file_list_lock);
}

DECLARE_WORK(g_file_track_work, cleanup_lost_files);

// When a process exits we want to go over the list of open files that it owns
// and move them
//  to the lost file list.  If we any were moved then schedule work to clean
//  them up. (I have found that if we do it right here that occasionally you end
//  up with a race in another thread to delete the file.)
bool check_open_file_list_on_exit_lock(struct list_head *file_list)
{
	bool		      found = false;
	struct table_element *data_ptr;
	struct table_element *tmp;

	list_for_each_entry_safe (data_ptr, tmp, file_list, siblings) {
		found = true;
		// Delete it from the list it is in
		list_del(&(data_ptr->siblings));
		// Add it to the lost file list
		list_add(&(data_ptr->siblings), &g_lost_file_list);
	}
	return found;
}
void check_open_file_list_on_exit(struct list_head *file_list)
{
	bool found = false;

	cb_spinlock(&g_file_list_lock);
	found = check_open_file_list_on_exit_lock(file_list);
	cb_spinunlock(&g_file_list_lock);

	if (found) {
		// Schedule the cleanup work to run immediately in the common
		// work queue. There may be other stuff in the Queue, but I do
		// not really care when it happens.
		schedule_work(&g_file_track_work);
	}
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

static int _show_file_tracking_table(struct HashTbl *	   hashTblp,
				     struct HashTableNode *nodep, void *priv)
{
	struct table_element *data_ptr = (struct table_element *)nodep;
	struct seq_file *     m	       = (struct seq_file *)priv;

	seq_printf(m, "%40s | %10llu | %6llu | %10s | %15s |\n",
		   data_ptr->value.path, data_ptr->key.inode,
		   (uint64_t)data_ptr->key.pid,
		   (data_ptr->value.isSpecialFile ? "YES" : "NO"),
		   getTypeStr(data_ptr->value.fileType));

	return ACTION_CONTINUE;
}

int cb_file_track_show_table(struct seq_file *m, void *v)
{
	seq_printf(m, "%40s | %10s | %6s | %11s | %15s |\n", "Path", "Inode",
		   "PID", "Is Special", "Type");
	cb_spinlock(&g_file_list_lock);

	hashtbl_for_each_generic(hash_table, _show_file_tracking_table, m);
	cb_spinunlock(&g_file_list_lock);

	return 0;
}
