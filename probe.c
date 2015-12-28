/*
 * probe.c
 *
 * Copyright (C) 2010-2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Functions in this file are doing runtime address resolution based on byte
 * code comparison in order to allow LKM-based LSM modules to access built-in
 * functions and variables which are not exported to LKMs.
 * Since functions in this file are assuming that using identical source code,
 * identical kernel config and identical compiler generates identical byte code
 * output, functions in this file may not work on some architectures and/or
 * environments.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/security.h>
#ifndef __init
#include <linux/init.h>
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
#error This module supports only 2.6.0 and later kernels.
#endif
#ifndef CONFIG_SECURITY
#error You must choose CONFIG_SECURITY=y for building this module.
#endif
#ifndef CONFIG_KALLSYMS
#error You must choose CONFIG_KALLSYMS=y for building this module.
#endif
#ifndef CONFIG_PROC_FS
#error You must choose CONFIG_PROC_FS=y for building this module.
#endif
#ifndef CONFIG_MODULES
#error You must choose CONFIG_MODULES=y for building this module.
#endif


/**
 * probe_kernel_read - Wrapper for kernel_read().
 *
 * @file:   Pointer to "struct file".
 * @offset: Starting position.
 * @addr:   Buffer.
 * @count:  Size of @addr.
 *
 * Returns return value from kernel_read().
 */
static int __init probe_kernel_read(struct file *file, unsigned long offset,
				    char *addr, unsigned long count)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 8)
	/*
	 * I can't use kernel_read() because seq_read() returns -EPIPE
	 * if &pos != &file->f_pos .
	 */
	mm_segment_t old_fs;
	unsigned long pos = file->f_pos;
	int result;
	file->f_pos = offset;
	old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_read(file, (void __user *)addr, count, &file->f_pos);
	set_fs(old_fs);
	file->f_pos = pos;
	return result;
#else
	return kernel_read(file, offset, addr, count);
#endif
}

/**
 * probe_find_symbol - Find function's address from /proc/kallsyms .
 *
 * @keyline: Function to find.
 *
 * Returns address of specified function on success, NULL otherwise.
 */
void *__init probe_find_symbol(const char *keyline)
{
	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		struct file_system_type *fstype = NULL;
		struct vfsmount *mnt = do_kern_mount("proc", 0, "proc", NULL);
#else
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = kern_mount(fstype);
#endif
		struct dentry *root;
		struct dentry *dentry;
		/*
		 * We embed put_filesystem() here because it is not exported.
		 */
		if (fstype)
			module_put(fstype->owner);
		if (IS_ERR(mnt))
			goto out;
		root = dget(mnt->mnt_root);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
		mutex_lock(&root->d_inode->i_mutex);
		dentry = lookup_one_len("kallsyms", root, 8);
		mutex_unlock(&root->d_inode->i_mutex);
#else
		down(&root->d_inode->i_sem);
		dentry = lookup_one_len("kallsyms", root, 8);
		up(&root->d_inode->i_sem);
#endif
		dput(root);
		if (IS_ERR(dentry))
			mntput(mnt);
		else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
			struct path path = { mnt, dentry };
			file = dentry_open(&path, O_RDONLY, current_cred());
#else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					   , current_cred()
#endif
					   );
#endif
		}
	}
	if (IS_ERR(file) || !file)
		goto out;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf) {
		int len;
		int offset = 0;
		while ((len = probe_kernel_read(file, offset, buf,
						PAGE_SIZE - 1)) > 0) {
			char *cp;
			buf[len] = '\0';
			cp = strrchr(buf, '\n');
			if (!cp)
				break;
			*(cp + 1) = '\0';
			offset += strlen(buf);
			cp = strstr(buf, keyline);
			if (!cp)
				continue;
			*cp = '\0';
			while (cp > buf && *(cp - 1) != '\n')
				cp--;
			entry = simple_strtoul(cp, NULL, 16);
			break;
		}
		kfree(buf);
	}
	filp_close(file, NULL);
out:
	return (void *) entry;
}



