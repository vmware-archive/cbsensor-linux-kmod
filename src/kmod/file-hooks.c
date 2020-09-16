/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_FILE | DS_HOOK)
#include "file-types.h"
#include "file-write-tracking.h"
#include "priv.h"
#include "process-tracking.h"

#include <linux/file.h>
#include <linux/magic.h>

#define N_ELEM(x) (sizeof(x) / sizeof(*x))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define DENTRY(a) (a)
#else
#define DENTRY(a) (a)->dentry, (a)->mnt
#endif

typedef struct special_file_t_ {
	char *name;
	int   len;
	int   enabled;

} special_file_t;

#define ENABLE_SPECIAL_FILE_SETUP(x) \
	{                            \
		x, sizeof(x) - 1, 1  \
	}
#define DISABLE_SPECIAL_FILE_SETUP(x) \
	{                             \
		x, sizeof(x) - 1, 0   \
	}

#define MAX_DISTANCE_FROM_START (PAGE_SIZE * 4)

//
// be sure to keep this value set to the smallest 'len' value in the
// special_files[] array below
//
// TODO: When removing support for 6.1.x old paths should be removed
#define MIN_SPECIAL_FILE_LEN 5
static const special_file_t special_files[] = {
	ENABLE_SPECIAL_FILE_SETUP("/var/lib/cb"),
	ENABLE_SPECIAL_FILE_SETUP("/var/log"),
	ENABLE_SPECIAL_FILE_SETUP("/srv/bit9/data"),
	ENABLE_SPECIAL_FILE_SETUP("/sys"),
	ENABLE_SPECIAL_FILE_SETUP("/proc"),
	ENABLE_SPECIAL_FILE_SETUP("/var/opt/carbonblack"),
	DISABLE_SPECIAL_FILE_SETUP(""),
	DISABLE_SPECIAL_FILE_SETUP(""),
	DISABLE_SPECIAL_FILE_SETUP(""),
	DISABLE_SPECIAL_FILE_SETUP(""),
	DISABLE_SPECIAL_FILE_SETUP(""),
	DISABLE_SPECIAL_FILE_SETUP(""),
};

static void do_file_write_event(struct file *file);
static void do_file_close_event(struct file *file);

//
// FUNCTION:
//   isSpecialFile()
//
// DESCRIPTION:
//   we'll skip any file that lives below any of the directories listed in
//   in the special_files[] array.
//
// PARAMS:
//   char *pathname - full path + filename to test
//   int len - length of the full path and filename
//
// RETURNS:
//   0 == no match
//
//
int isSpecialFile(char *pathname, int len)
{
	int i;

	//
	// bail out if we've got no chance of a match
	//
	if (len < MIN_SPECIAL_FILE_LEN) {
		return 0;
	}

	for (i = 0; i < N_ELEM(special_files); i++) {
		//
		// Skip disabled elements
		//
		if (!special_files[i].enabled) {
			continue;
		}

		//
		// if the length of the path we're testing is shorter than this
		// special file, it can't possibly be a match
		//
		if (special_files[i].len > len) {
			continue;
		}

		//
		// still here, do the compare. We know that the path passed in
		// is >= this special_file[].len so we'll just compare up the
		// length of the special file itself. If we match up to that
		// point, the path being tested is or is below this
		// special_file[].name
		//
		if (strncmp(pathname, special_files[i].name,
			    special_files[i].len) == 0) {
			return -1;
		}
	}

	return 0;
}

bool is_interesting_file(umode_t mode)
{
	return (S_ISREG(mode) && (!S_ISDIR(mode)) && (!S_ISLNK(mode)));
}

//. Attempt to get super block from dentry's inode before dentry's sb
static struct super_block *_sb_from_dentry(struct dentry *dentry)
{
	struct super_block *sb = NULL;
	// Can't get dentry info return NULL
	if (!dentry) {
		goto out;
	}
	// Try dentry inode before dentry's sb
	if (dentry->d_inode) {
		sb = dentry->d_inode->i_sb;
	}
	if (sb) {
		goto out;
	}
	// This might not exactly be the sb we are looking for
	sb = dentry->d_sb;

out:
	return sb;
}

// Attempt to get super block from inode of file or and dentry
static struct super_block *_sb_from_file(struct file *file)
{
	struct super_block *sb = NULL;

	if (!file) {
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	if (file->f_inode) {
		sb = file->f_inode->i_sb;
	}
	if (sb) {
		goto out;
	}
#endif
	sb = _sb_from_dentry(file->f_path.dentry);

out:
	return sb;
}

#if 0
static dev_t get_dev_from_file(struct file *filep)
{
	dev_t		    dev = 0;
	struct super_block *sb	= _sb_from_file(filep);

	if (sb) {
		dev = sb->s_dev;
	}
	return dev;
}
#endif

static inline bool __is_special_filesystem(struct super_block *sb)
{
	if (!sb) {
		return false;
	}

	switch (sb->s_magic) {
	// Special Kernel File Systems
	case CGROUP_SUPER_MAGIC:
	case SELINUX_MAGIC:
	case SYSFS_MAGIC:
	case PROC_SUPER_MAGIC:
	case SOCKFS_MAGIC:
	case DEVPTS_SUPER_MAGIC:
	case FUTEXFS_SUPER_MAGIC:
	case ANON_INODE_FS_MAGIC:
	case DEBUGFS_MAGIC:
#ifdef PIPEFS_MAGIC
	case PIPEFS_MAGIC:
#endif /* PIPEFS_MAGIC */
#ifdef BINDERFS_SUPER_MAGIC
	case BINDERFS_SUPER_MAGIC:
#endif /* BINDERFS_SUPER_MAGIC */
#ifdef BPF_FS_MAGIC
	case BPF_FS_MAGIC:
#endif /* BPF_FS_MAGIC */
#ifdef TRACEFS_MAGIC
	case TRACEFS_MAGIC
#endif /* TRACEFS_MAGIC */

		return true;

		default:
		return false;
	}

	return false;
}

static inline bool __is_stacked_filesystem(struct super_block *sb)
{
#ifndef CIFS_MAGIC_NUMBER
#define CIFS_MAGIC_NUMBER 0xFF534D42
#endif /* CIFS_MAGIC_NUMBER */
#ifndef GFS2_MAGIC
#define GFS2_MAGIC 0x01161970
#endif /* GFS2_MAGIC */
#ifndef CEPH_SUPER_MAGIC
#define CEPH_SUPER_MAGIC 0x00c36400
#endif /* CEPH_SUPER_MAGIC */
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif /* FUSE_SUPER_MAGIC */

	if (!sb) {
		return false;
	}

	switch (sb->s_magic) {
	// Networking File Systems
	case NFS_SUPER_MAGIC:
	case CIFS_MAGIC_NUMBER:
	case GFS2_MAGIC:
	case CEPH_SUPER_MAGIC:

	// Stacked File Systems
	case FUSE_SUPER_MAGIC:
#ifdef ECRYPTFS_SUPER_MAGIC
	case ECRYPTFS_SUPER_MAGIC:
#endif /* ECRYPTFS_SUPER_MAGIC */
#ifdef OVERLAYFS_SUPER_MAGIC
	case OVERLAYFS_SUPER_MAGIC:
#endif /* OVERLAYFS_SUPER_MAGIC */
		return true;

	default:
		return false;
	}

	return false;
}

bool may_skip_dentry_event_for_special_fs(struct dentry *dentry)
{
	struct super_block *sb = _sb_from_dentry(dentry);

	// We can still create events without knowing the filesystem
	if (!sb) {
		return false;
	}
	return __is_special_filesystem(sb);
}

bool may_skip_file_event_for_special_fs(struct file *filep)
{
	struct super_block *sb = _sb_from_file(filep);

	// We can still create events without knowing the filesystem
	if (!sb) {
		return false;
	}
	return __is_special_filesystem(sb);
}

bool may_skip_unsafe_vfs_calls(struct file *filep)
{
	struct super_block *sb = _sb_from_file(filep);

	// We want to skip when things are uncertain for unsafe procedures
	if (!sb) {
		return true;
	}
	return (__is_special_filesystem(sb) || __is_stacked_filesystem(sb));
}

struct inode *get_inode_from_dentry(struct dentry *dentry)
{
	// Skip if dentry is null
	if (!dentry) return NULL;
	if (!dentry->d_inode) return NULL;

	// dig out inode
	return dentry->d_inode;
}

struct inode *get_inode_from_file(struct file *file)
{
	if (!file) return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	// The cached inode may be NULL, but the calling code will handle that
	return file->f_inode;
#else
	// Skip if dentry or inode is null
	if (!file->f_path.dentry) return NULL;
	if (!file->f_path.dentry->d_inode) return NULL;

	// dig out inode
	return file->f_path.dentry->d_inode;
#endif
}

static void logger_on_generic_file_event(struct dentry *    dentry,
					 enum CB_EVENT_TYPE eventType,
					 int		    param)
{
	struct CB_EVENT *event;
	char *		 pathname;
	uint64_t	 pathsz;
	struct inode *	 inodep = NULL;
	uint64_t	 ino	= 0;
	pid_t		 pid	= getpid(current);

	if (cbIngoreProcess(pid)) {
		return;
	}

	if (may_skip_dentry_event_for_special_fs(dentry)) {
		return;
	}

	event = logger_alloc_event(eventType, current);
	if (!event) {
		return;
	}

	//
	// Populate the event
	//
	pathname = dentry_to_path(dentry, event->fileGeneric.path);
	if (IS_ERR(pathname)) {
		//
		// Just free the event if we couldn't figure out the file name
		//
		logger_free_event_on_error(event);
		return;
	}

	pathsz = (&event->fileGeneric.path[PATH_MAX] - pathname);
	memmove(event->fileGeneric.path, pathname, pathsz);

	switch (eventType) {
	case CB_EVENT_TYPE_FILE_CREATE:
		PR_DEBUG_RATELIMITED("Create %s mode:0x%X",
				     event->fileGeneric.path, param);
		break;

	case CB_EVENT_TYPE_FILE_DELETE:
		inodep = get_inode_from_dentry(dentry);
		if (inodep) {
			ino = inodep->i_ino;
		}
		PR_DEBUG_RATELIMITED(
			"Checking if deleted inode [%llu] was banned.", ino);
		if (cbClearBannedProcessInode(ino)) {
			PR_DEBUG("%llu was removed from banned inode table.",
				 ino);
		}
		PR_DEBUG_RATELIMITED("Delete %s", event->fileGeneric.path);
		break;

	default:
		break;
	}

	if (!is_process_tracked(pid)) {
		PR_DEBUG("Fileop pid=%d not tracked", pid);
		create_process_start_event(current);
	}

	//
	// Queue it to be sent to usermode
	//
	logger_submit_event(event);
}

// @@REVIEW: need to test for S_IFREG in mode?
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int on_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
#else
int on_inode_create(struct inode *dir, struct dentry *dentry, int mode)
#endif
{
	int xcode;
	MODULE_GET();
	xcode = g_original_ops_ptr->inode_create(dir, dentry, mode);
	TRY(xcode == 0);

	logger_on_generic_file_event(dentry, CB_EVENT_TYPE_FILE_CREATE, mode);

CATCH_DEFAULT:
	MODULE_PUT();
	return xcode;
}

int on_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	int xcode;
	MODULE_GET();
	xcode = g_original_ops_ptr->inode_unlink(dir, dentry);
	TRY(xcode == 0);

	logger_on_generic_file_event(dentry, CB_EVENT_TYPE_FILE_DELETE, 0);

CATCH_DEFAULT:
	MODULE_PUT();
	return xcode;
}

int on_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
		    struct inode *new_dir, struct dentry *new_dentry)
{
	int xcode;
	MODULE_GET();
	xcode = g_original_ops_ptr->inode_rename(old_dir, old_dentry, new_dir,
						 new_dentry);
	TRY(xcode == 0);

	logger_on_generic_file_event(old_dentry, CB_EVENT_TYPE_FILE_DELETE, 0);
	logger_on_generic_file_event(new_dentry, CB_EVENT_TYPE_FILE_CREATE, 0);

CATCH_DEFAULT:
	MODULE_PUT();
	return xcode;
}

int on_file_permission(struct file *file, int mask)
{
	bool write = (mask & MAY_WRITE) == MAY_WRITE;
	int  xcode = 0;
	MODULE_GET();

	xcode = g_original_ops_ptr->file_permission(file, mask);
	TRY(xcode == 0);

	if (write) {
		do_file_write_event(file);
	}

CATCH_DEFAULT:
	MODULE_PUT();
	return xcode;
}

void on_file_free(struct file *file)
{
	bool has_write = ((file->f_mode & FMODE_WRITE) != 0);
	MODULE_GET();

	g_original_ops_ptr->file_free_security(file);

	if (has_write) {
		do_file_close_event(file);
	}

	MODULE_PUT();
}

long (*cb_orig_sys_write)(unsigned int fd, const char __user *buf,
			  size_t count);

// This detects the file type after the first write happens.  We still send the
// events from the LSM hook because the kernel panics the second time a file is
// opened when we attempt to read the path from this hook.
// Because we detect the type after the first write, I added logic that will
// redetect the type on a write to the beginning of the file.  (So if the file
// type changes we will detect it.)
// NOTE: I have to read the file type here so I have access to the number bytes
// written to the file.  I need this to decide if we wrote into the area that
// will help us identify the file type.
asmlinkage long cb_sys_write(unsigned int fd, const char __user *buf,
			     size_t count)
{
	long		       ret;
	struct inode *	       inode;
	struct file *	       file = NULL;
	loff_t		       pre_write_pos;
	loff_t		       post_write_pos;
	enum CB_FILE_TYPE      fileType = filetypeUnknown;
	char		       buffer[MAX_FILE_BYTES_TO_DETERMINE_TYPE];
	struct file_type_state state;
	pid_t		       last_tgid;
	bool		       found_entry;
	bool		       commit_change = false;

	MODULE_GET();

	// Do the actual write first.  This way if the type is changed we will
	// detect it later.
	ret = cb_orig_sys_write(fd, buf, count);
	TRY(ret > -1);

	// Get a local reference to the file
	file = fget(fd);
	TRY(file != NULL);

	inode = get_inode_from_file(file);
	TRY(inode != NULL);

	// Skip if not interesting
	if (!is_interesting_file(inode->i_mode)) {
		goto CATCH_DEFAULT;
	}

	// Special file systems are not tracked
	if (may_skip_file_event_for_special_fs(file)) {
		goto CATCH_DEFAULT;
	}

	post_write_pos = file->f_pos;
	pre_write_pos  = post_write_pos - ret;

	// We should limit how far we want to potentially vfs_llseek.
	// Being more than a few pages away seems far enough to do nothing
	if (pre_write_pos < 0 || pre_write_pos >= MAX_DISTANCE_FROM_START) {
		goto CATCH_DEFAULT;
	}

	last_tgid = 0;
	memset(&state, 0, sizeof(state));
	found_entry = get_file_entry_data(file, &last_tgid, &state, NULL);

	// We do not care about untracked or special files
	if (!found_entry || state.isSpecialFile) {
		goto CATCH_DEFAULT;
	}

	if (pre_write_pos < MAX_FILE_BYTES_TO_DETERMINE_TYPE) {
		if (state.didReadType) {
			commit_change = true;
		}
		state.didReadType = false;
	}

	// Utilize the userspace buffer to get file contents
	if (pre_write_pos == 0 && ret >= MAX_FILE_BYTES_TO_DETERMINE_TYPE) {
		if (copy_from_user(buffer, buf,
				   MAX_FILE_BYTES_TO_DETERMINE_TYPE)) {
			goto CATCH_DEFAULT;
		}
		determine_file_type(buffer, MAX_FILE_BYTES_TO_DETERMINE_TYPE,
				    &fileType, true);
		//        PR_DEBUG("Detected file %s of type %s",
		//        fileProcess->path, file_type_str(fileType));
		if (state.fileType != fileType || !state.didReadType) {
			commit_change = true;
		}
		state.fileType	  = fileType;
		state.didReadType = true;
		goto CATCH_DEFAULT;
	}

	// Previously determined the type, so there is
	// no need seek/read/seek when it hasn't changed
	if (state.didReadType) {
		goto CATCH_DEFAULT;
	}

	// Everything else down this path require vfs_read
	if (!state.try_vfs_read) {
		goto CATCH_DEFAULT;
	}

	// We do not want to perform any VFS calls on this file
	if (may_skip_unsafe_vfs_calls(file)) {
		state.try_vfs_read = false;
		commit_change	   = true;
		goto CATCH_DEFAULT;
	}

	// If we made it this far. Commit the change.
	commit_change = true;

	// The file system file ops do not support vfs_llseek or vfs_read
	if (!file->f_op || (!file->f_op->read && !file->f_op->aio_read) ||
	    (!file->f_op->llseek)) {
		state.try_vfs_read = false;
		goto CATCH_DEFAULT;
	}

	// Attempt get beginning of file contents via VFS
	// There's been enough checks on file position and boundaries.
	{
		loff_t	     pos  = 0;
		ssize_t	     size = 0;
		mm_segment_t oldfs;
		fmode_t	     mode;
		loff_t	     llseek_ret;

		// Save the real mode and force the ability to read in case the
		// file was opened write only
		mode = file->f_mode;
		file->f_mode |= FMODE_READ;
		file->f_mode |= FMODE_LSEEK;

		// Seek to the beginning of the file so we can read the data we
		// want.
		llseek_ret = vfs_llseek(file, 0, SEEK_SET);
		if (llseek_ret != 0) {
			state.try_vfs_read = false;
			commit_change	   = true;
			// Restore the real file mode
			file->f_mode = mode;
			goto CATCH_DEFAULT;
		}

		// Disable memory checks because we are passing in a kernel
		// buffer instead of a user buffer
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		size = vfs_read(file, buffer, MAX_FILE_BYTES_TO_DETERMINE_TYPE,
				&pos);
		set_fs(oldfs);

		// Seek back to where the file was be so that the next write
		// will work
		llseek_ret = vfs_llseek(file, post_write_pos, SEEK_SET);
		if (llseek_ret != post_write_pos) {
			state.try_vfs_read = false;
			// PRINTK(KERN_WARNING, "Unable to seek back to post
			// write position: %lld[%#llx] on file:%s",
			//    post_write_pos, llseek_ret, fileProcess->path);
		}

		// Restore the real file mode
		file->f_mode = mode;

		if (size <= 0) {
			state.try_vfs_read = false;
		} else {
			determine_file_type(buffer, size, &fileType, true);
			// PR_DEBUG("Detected file %s of type %s",
			// fileProcess->path, file_type_str(fileType));
			state.fileType	  = fileType;
			state.didReadType = true;
		}
	}

CATCH_DEFAULT:
	if (commit_change) {
		set_file_entry_data(file, NULL, &state, NULL);
	}
	if (file) {
		fput(file);
	}
	MODULE_PUT();
	return ret;
}

static void do_file_write_event(struct file *file)
{
	bool	      found;
	struct inode *inode;
	pid_t	      pid	= getpid(current);
	pid_t	      last_tgid = 0;

	if (cbIngoreProcess(pid)) {
		return;
	}

	if (!should_log(CB_EVENT_TYPE_FILE_CREATE)) {
		return;
	}

	inode = get_inode_from_file(file);
	if (!inode) {
		return;
	}

	// Skip if not interesting
	if (!is_interesting_file(inode->i_mode)) {
		return;
	}

	// Special file systems don't need to create events
	if (may_skip_file_event_for_special_fs(file)) {
		return;
	}

	found = get_file_entry_data(file, &last_tgid, NULL, NULL);
	if (found) {
		if (pid == last_tgid) {
			return;
		}

		// Check to see if the process is tracked already
		if (!is_process_tracked(pid)) {
			PR_DEBUG("Fileop pid=%d not tracked", pid);
			create_process_start_event(current);
		}

		update_file_entry(file, pid);
	} else {
		// Check to see if the process is tracked already
		if (!is_process_tracked(pid)) {
			PR_DEBUG("Fileop pid=%d not tracked", pid);
			create_process_start_event(current);
		}
		insert_file_entry(file, pid);
	}

	if (cbClearBannedProcessInode(inode->i_ino)) {
		PR_DEBUG("%lu was removed from banned inode table.",
			 inode->i_ino);
	}
}

static void do_file_close_event(struct file *file)
{
	// This process is not interesting yet
	if (is_file_tracked(file)) {
		remove_file_entry(file);
	}
}
