/*
 * Copyright 2016-2020 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define DS_MYSUBSYS (DS_FILE | DS_PROC | DS_MOD)
#include "priv.h"

bool file_helper_init(void)
{
	//
	// Find where the dentry pointer is.
	//
	return true;
}

char *dentry_to_path(struct dentry *dentry, char *buf)
{
	char *xcode = NULL;
	CANCEL_CB_RESOLVED(dentry_path);
	return CB_RESOLVED(dentry_path)(dentry, buf, PATH_MAX);
}

bool file_get_path(struct file *file, char *buffer, char **pathname)
{
	struct path *path = &file->f_path;

	if (!pathname) {
		return false;
	}

	// Problem here is that dentry_path, which solves pathing issues in
	// chroot/namespace cases is not adequate for the normal use case that
	// d_path satisfies. These two function differ in the way in which they
	// determine the root dentry (d_path by get_fs_root and dentry_path by
	// explicitly walking the dentry table). In the dentry_path case, we
	// consistently miss the root node. So each solution is the right
	// solution for that specific case, we just need to know when to use
	// each.

	// If we failed to resolve the symbol, i.e. we're on a 2.6.32 kernel or
	// it just doesn't resolve, or the namespace which current_chrooted()
	// needs does not exist, default to the d_path option.
	*pathname = NULL;
	path_get(path);
	if (current->nsproxy && CB_CHECK_RESOLVED(current_chrooted) &&
	    CB_RESOLVED(current_chrooted)()) {
		*pathname = dentry_to_path(path->dentry, buffer);
	} else {
		*pathname = d_path(path, buffer, PATH_MAX);
	}

	if (IS_ERR_OR_NULL(*pathname)) {
		*pathname = buffer;

		strncpy(*pathname, file->f_dentry->d_name.name,
			min(file->f_dentry->d_name.len,
			    (unsigned int)PATH_MAX));
		(*pathname)[file->f_dentry->d_name.len] = 0;

		PRINTK(KERN_WARNING,
		       "Path lookup failed, using |%s| as file name",
		       *pathname);

		path_put(path);
		return false;
	}

	path_put(path);
	return true;
}
