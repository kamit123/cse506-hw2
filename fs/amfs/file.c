/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "amfs.h"
#include "amfs_ioctl.h"
#include <linux/xattr.h>
#include <linux/fs.h>

struct amfs_getdents_callback {
	struct dir_context ctx;
	struct dir_context *caller;
	struct super_block *sb;
	struct dentry *parent_lower_dentry;
	struct vfsmount *parent_lower_mnt;
	int filldir_called;
	int entries_written;
};

static int amfs_write_pattdb(char *pattdb_src, struct list_head *patt_list)
{
	struct file *pattdb;
	int err = 0;
	mm_segment_t fs = get_fs();
	struct amfs_virus_pattern *pos;

	pattdb = filp_open(pattdb_src, O_RDONLY | O_TRUNC, 0);
	if (IS_ERR(pattdb)) {
		printk(KERN_ERR "error opening pattdb\n");
		err = PTR_ERR(pattdb);
		goto out;
	}

	set_fs(get_ds());
	list_for_each_entry(pos, patt_list, patt_list) {
		pattdb->f_op->write(pattdb, pos->pattern,
				    strlen(pos->pattern), &pattdb->f_pos);
		pattdb->f_op->write(pattdb, "\n", 1, &pattdb->f_pos);
	}
out:
	set_fs(fs);
	filp_close(pattdb, NULL);
	return err;
}

static int amfs_is_infected(struct list_head *patt_list, char *buf,
			    size_t count)
{
	struct amfs_virus_pattern *pos;
	int infected = 0;

	list_for_each_entry(pos, patt_list, patt_list) {
		if (strnstr(buf, pos->pattern, count) != NULL) {
			infected = 1;
			break;
		}
	}

	return infected;
}

static int amfs_is_bad_file(struct file *file)
{
	return amfs_is_bad_dentry(file->f_path.dentry,
				  file->f_inode->i_sb);
}

#ifdef EXTRA_CREDIT
static int amfs_is_good(struct file *file)
{
	char *state = NULL;
	int rc = 0;
	time_t version;

	state = kmalloc(AMFS_XATTR_SSV_MAX, GFP_KERNEL);
	if (state == NULL) {
		printk(KERN_ERR "error while kmalloc for state\n");
		rc = -ENOMEM;
		goto out;
	}
	if (vfs_getxattr
	    (file->f_path.dentry, AMFS_XATTR_SSN, state,
	     AMFS_XATTR_SSV_MAX) > 0
	    && vfs_getxattr(file->f_path.dentry, AMFS_XATTR_VER, &version,
			    sizeof(version)) > 0) {
		if (strcmp(state, AMFS_XATTR_SSG) == 0
		    && AMFS_SB(file->f_path.dentry->d_sb)->version ==
		    version) {
			rc = 1;
		}
	}

out:
	kfree(state);
	return rc;
}
#endif

static ssize_t amfs_read(struct file *file, char __user * buf,
			 size_t count, loff_t * ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	char *kbuf = NULL;
	struct amfs_sb_info *sbi = AMFS_SB(dentry->d_sb);

	if (S_ISREG(file->f_inode->i_mode)) {
		if (amfs_is_bad_file(file)) {
			printk(KERN_INFO "determined pre-bad in read\n");
			err = -EINVAL;
			goto out;
		}
	}

	lower_file = amfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0) {
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));

		if (S_ISREG(file->f_inode->i_mode)) {
			kbuf = kmalloc(err, GFP_KERNEL);
			if (kbuf == NULL) {
				printk(KERN_ERR
				       "error while kmalloc for kbuf\n");
				err = -ENOMEM;
				goto out;
			}
			if (copy_from_user(kbuf, buf, err)) {
				printk(KERN_ERR
				       "error copying buf to kbuf\n");
				err = -EINVAL;
				goto out;
			}

			if (amfs_is_infected(&sbi->patt_list, kbuf, err)) {
				vfs_setxattr(dentry, AMFS_XATTR_SSN,
					     AMFS_XATTR_SSB,
					     strlen(AMFS_XATTR_SSB) + 1,
					     0);
				vfs_setxattr(dentry, AMFS_XATTR_VER,
					     &sbi->version,
					     sizeof(sbi->version), 0);
				err = -EINVAL;
				goto out;
			}
		}
	}

out:
	kfree(kbuf);
	return err;
}

static ssize_t amfs_write(struct file *file, const char __user * buf,
			  size_t count, loff_t * ppos)
{
	int err;
	char *kbuf = NULL;
	struct amfs_sb_info *sbi = AMFS_SB(file->f_path.dentry->d_sb);
	struct dentry *dentry = file->f_path.dentry;
	struct file *lower_file;

	if (S_ISREG(file->f_inode->i_mode)) {
		if (amfs_is_bad_file(file)) {
			printk(KERN_INFO "determined pre-bad in write\n");
			err = -EINVAL;
			goto out;
		}

		kbuf = kmalloc(count, GFP_KERNEL);
		if (kbuf == NULL) {
			printk(KERN_ERR "error while kmalloc for kbuf\n");
			err = -ENOMEM;
			goto out;
		}
		if (copy_from_user(kbuf, buf, count)) {
			printk(KERN_ERR "error copying buf to kbuf\n");
			err = -EINVAL;
			goto out;
		}

		if (amfs_is_infected(&sbi->patt_list, kbuf, count)) {
			printk(KERN_INFO "write buf is infected\n");
			err = -EINVAL;
			goto out;
		}
	}

	lower_file = amfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(dentry->d_inode,
					file_inode(lower_file));
	}

out:
	kfree(kbuf);
	return err;
}

static int amfs_filldir(struct dir_context *ctx, const char *lower_name,
			int lower_namelen, loff_t offset, u64 ino,
			unsigned int d_type)
{
	struct amfs_getdents_callback *buf =
	    container_of(ctx, struct amfs_getdents_callback, ctx);
	int rc = 0;
	struct path lower_path;
	struct dentry *d;

	if (buf->parent_lower_dentry == NULL
	    || buf->parent_lower_mnt == NULL) {
		printk(KERN_ERR "null parent dentry and mnt point\n");
		goto out;
	}

	mutex_unlock(&buf->parent_lower_dentry->d_inode->i_mutex);
	rc = vfs_path_lookup(buf->parent_lower_dentry,
			     buf->parent_lower_mnt, lower_name, 0,
			     &lower_path);
	if (rc) {
		printk(KERN_ERR "error in vfs_lookup in amfs_filldir\n");
		goto out;
	}
	mutex_lock(&buf->parent_lower_dentry->d_inode->i_mutex);
	d = lower_path.dentry;
	if (amfs_is_bad_dentry(d, buf->sb) == 1) {
		printk(KERN_INFO "skipping bad file from filldir\n");
		goto out;
	}

	buf->caller->pos = buf->ctx.pos;
	rc = !dir_emit(buf->caller, lower_name, lower_namelen, ino,
		       d_type);
	if (!rc)
		buf->entries_written++;

out:
	return rc;
}

static int amfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = amfs_lower_file(file);
	struct amfs_getdents_callback buf = {
		.ctx.actor = amfs_filldir,
		.caller = ctx,
		.sb = file->f_inode->i_sb,
		.parent_lower_dentry = lower_file->f_path.dentry,
		.parent_lower_mnt = lower_file->f_path.mnt,
	};
	struct dentry *dentry = file->f_path.dentry;

	err = iterate_dir(lower_file, &buf.ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					file_inode(lower_file));

	return err;
}

static int amfs_ioctl_removepattern(unsigned long arg,
				    struct list_head *patt_list,
				    char *pattdb_src)
{
	int arglen, err = 0, flag = 0;
	char *karg = NULL;
	struct amfs_virus_pattern *pos, *temp;

	arglen = strlen_user((char *) arg);
	if (arglen <= 0) {
		printk(KERN_ERR "error getting length of arg\n");
		err = -EINVAL;
		goto out;
	}

	karg = kmalloc(arglen, GFP_KERNEL);
	if (karg == NULL) {
		printk(KERN_ERR "error while kmalloc for karg\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user(karg, (char *) arg, arglen)) {
		printk(KERN_ERR "error copying arg to karg\n");
		err = -EINVAL;
		goto out;
	}

	list_for_each_entry_safe(pos, temp, patt_list, patt_list) {
		if (strcmp(pos->pattern, karg) == 0) {
			flag = 1;
			list_del(&pos->patt_list);
		}
	}

	if (flag == 0)
		err = -ENOENT;
	else
		amfs_write_pattdb(pattdb_src, patt_list);
out:
	kfree(karg);
	return err;
}

static int amfs_ioctl_addpattern(unsigned long arg,
				 struct list_head *patt_list,
				 char *pattdb_src)
{
	int arglen, err = 0;
	struct amfs_virus_pattern *patt;

	arglen = strlen_user((char *) arg);
	if (arglen <= 0) {
		printk(KERN_ERR "error getting length of arg\n");
		err = -EINVAL;
		goto out;
	}

	patt = kmalloc(sizeof(struct amfs_virus_pattern), GFP_KERNEL);
	if (patt == NULL) {
		printk(KERN_ERR "error while kmalloc for patt\n");
		err = -ENOMEM;
		goto out;
	}
	patt->pattern = kmalloc(arglen, GFP_KERNEL);
	if (patt->pattern == NULL) {
		printk(KERN_ERR "error while kmalloc for patt->pattern\n");
		err = -ENOMEM;
		goto out;
	}
	if (copy_from_user(patt->pattern, (char *) arg, arglen)) {
		printk(KERN_ERR "error copying arg to patt->pattern\n");
		err = -EINVAL;
		goto out;
	}

	list_add(&patt->patt_list, patt_list);
	amfs_write_pattdb(pattdb_src, patt_list);

out:
	return err;
}

static int amfs_ioctl_getpatterns(unsigned long arg,
				  struct list_head *patt_list)
{
	struct amfs_patterns_info *patterns_info = NULL;
	struct amfs_virus_pattern *pos;
	int err = 0, count = -1, i;

	patterns_info =
	    kmalloc(sizeof(struct amfs_patterns_info), GFP_KERNEL);
	if (patterns_info == NULL) {
		printk(KERN_ERR "error while kmalloc for patterns\n");
		err = -ENOMEM;
		goto out;
	}

	list_for_each_entry(pos, patt_list, patt_list) {
		count++;
		if (count == 256) {
			printk(KERN_ERR
			       "more than 256 patterns, not all returned to user\n");
			break;
		}

		if (strlen(pos->pattern) > 255)
			printk(KERN_ERR
			       "skipping pattern %s as length > 255\n",
			       pos->pattern);
		else
			strcpy(patterns_info->patterns[count],
			       pos->pattern);
	}
	patterns_info->count = count + 1;

	if (copy_to_user
	    ((struct amfs_patterns_info *) arg, patterns_info,
	     sizeof(struct amfs_patterns_info))) {
		printk(KERN_ERR "error copying patterns_info to arg\n");
		err = -EINVAL;
		goto out;
	}
	for (i = 0; i < patterns_info->count; ++i) {
		if (copy_to_user
		    (((struct amfs_patterns_info *) arg)->patterns[i],
		     patterns_info->patterns[i],
		     strlen(patterns_info->patterns[i]) + 1)) {
			printk(KERN_ERR
			       "error copying patterns_info to arg\n");
			err = -EINVAL;
			goto out;
		}
	}

out:
	kfree(patterns_info);
	return err;
}

static long amfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	struct amfs_sb_info *sbi = AMFS_SB(file->f_path.dentry->d_sb);

	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err =
		    lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));

	switch (cmd) {
	case AMFS_IOCTL_GETPATTERNS:
		err = amfs_ioctl_getpatterns(arg, &sbi->patt_list);
		if (err) {
			printk(KERN_ERR
			       "error in amfs_ioctl_getpatterns\n");
			goto out;
		}
		break;

	case AMFS_IOCTL_ADDPATTERN:
		err =
		    amfs_ioctl_addpattern(arg, &sbi->patt_list,
					  sbi->pattdb_src);
		if (err) {
			printk(KERN_ERR
			       "error in amfs_ioctl_addpattern\n");
			goto out;
		}
		sbi->version = get_seconds();
		break;

	case AMFS_IOCTL_REMOVEPATTERN:
		err = amfs_ioctl_removepattern(arg, &sbi->patt_list,
					       sbi->pattdb_src);
		if (err) {
			printk(KERN_ERR
			       "error in amfs_ioctl_addpattern\n");
			goto out;
		}
		sbi->version = get_seconds();
		break;

	default:
		printk(KERN_ERR "ioctl command not supported\n");
	}
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long amfs_compat_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int amfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite =
	    ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = amfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "amfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!AMFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "amfs: lower mmap failed %d\n",
			       err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops;	/* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &amfs_vm_ops;

	file->f_mapping->a_ops = &amfs_aops;	/* set our aops */
	if (!AMFS_F(file)->lower_vm_ops)	/* save for our ->fault */
		AMFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

#ifdef EXTRA_CREDIT
static int amfs_is_infected_file(struct file *file)
{
	int rc = 0, size_read, psize_read = 0, tsize_read, flag = 0;
	char *buf = NULL, *pbuf = NULL, *cbuf = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct amfs_sb_info *sbi = AMFS_SB(dentry->d_sb);
	mm_segment_t fs;

	if (!S_ISREG(file->f_inode->i_mode)) {
		printk(KERN_INFO "file is not a regular file\n");
		rc = -EINVAL;
		goto out;
	}

	if (amfs_is_bad_file(file)) {
		printk(KERN_INFO "determined pre-bad in open\n");
		rc = 1;
		goto out;
	}
	if (amfs_is_good(file)) {
		printk(KERN_INFO "determined pre-good in open\n");
		rc = 0;
		goto out;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	pbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	cbuf = kmalloc(2 * PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL || pbuf == NULL || cbuf == NULL) {
		printk(KERN_ERR "error while kmalloc for buf\n");
		rc = -ENOMEM;
		goto out;
	}

	fs = get_fs();
	set_fs(get_ds());
	while ((size_read =
		file->f_op->read(file, buf, PAGE_SIZE,
				 &file->f_pos)) > 0) {
		memcpy(cbuf, buf, size_read);
		memcpy(&cbuf[size_read], pbuf, psize_read);
		tsize_read = size_read + psize_read;
		if (amfs_is_infected(&sbi->patt_list, cbuf, tsize_read)) {
			flag = 1;
			break;
		}

		memcpy(pbuf, buf, size_read);
		psize_read = size_read;
	}
	file->f_op->llseek(file, 0, SEEK_SET);
	set_fs(fs);

	if (amfs_is_bad_file(file)) {
		printk(KERN_INFO "determined bad while opening\n");
		rc = 1;
		goto out;
	}

	if (flag) {
		printk(KERN_INFO "determined bad while opening\n");
		vfs_setxattr(dentry, AMFS_XATTR_SSN, AMFS_XATTR_SSB,
			     strlen(AMFS_XATTR_SSB) + 1, 0);
		rc = 1;
	} else {
		printk(KERN_INFO "determined good while opening\n");
		vfs_setxattr(dentry, AMFS_XATTR_SSN, AMFS_XATTR_SSG,
			     strlen(AMFS_XATTR_SSG) + 1, 0);
		rc = 0;
	}
	vfs_setxattr(dentry, AMFS_XATTR_VER, &sbi->version,
		     sizeof(sbi->version), 0);

out:
	kfree(buf);
	kfree(pbuf);
	kfree(cbuf);

	return rc;
}
#endif

static int amfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
	    kzalloc(sizeof(struct amfs_file_info), GFP_KERNEL);
	if (!AMFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link amfs's file struct to lower's */
	amfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file =
	    dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = amfs_lower_file(file);
		if (lower_file) {
			amfs_set_lower_file(file, NULL);
			fput(lower_file);	/* fput calls dput for lower_dentry */
		}
	} else {
		amfs_set_lower_file(file, lower_file);
		if (S_ISREG(file->f_inode->i_mode)) {
			if (file->f_flags & O_TRUNC) {
				printk(KERN_INFO
				       "file opened using O_TRUNC, hence no evaluation required.\n");
				goto out;
			}

			if (amfs_is_bad_file(file)) {
				printk(KERN_INFO
				       "determined bad while opening\n");
				err = -EINVAL;
				goto out;
			}
#ifdef EXTRA_CREDIT
			if (amfs_is_infected_file(file) == 1) {
				printk(KERN_INFO
				       "file tried to open is infected\n");
				err = -ENOENT;
			}
#endif
		}
	}

out:
	if (err)
		kfree(AMFS_F(file));
	else
		fsstack_copy_attr_all(inode, amfs_lower_inode(inode));
out_err:
	return err;
}

static int amfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int amfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = amfs_lower_file(file);
	if (lower_file) {
		amfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(AMFS_F(file));
	return 0;
}

static int amfs_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = amfs_lower_file(file);
	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	amfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int amfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t amfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
			     unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file);	/* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

static ssize_t amfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
			      unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file);	/* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t amfs_file_llseek(struct file *file, loff_t offset,
			       int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = amfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Amfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t amfs_read_iter(struct kiocb * iocb, struct iov_iter * iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file);	/* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
out:
	return err;
}

/*
 * Amfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t amfs_write_iter(struct kiocb * iocb, struct iov_iter * iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file);	/* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
					file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations amfs_main_fops = {
	.llseek = generic_file_llseek,
	.read = amfs_read,
	.write = amfs_write,
	.unlocked_ioctl = amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = amfs_compat_ioctl,
#endif
	.mmap = amfs_mmap,
	.open = amfs_open,
	.flush = amfs_flush,
	.release = amfs_file_release,
	.fsync = amfs_fsync,
	.fasync = amfs_fasync,
	.aio_read = amfs_aio_read,
	.aio_write = amfs_aio_write,
	.read_iter = amfs_read_iter,
	.write_iter = amfs_write_iter,
};

/* trimmed directory options */
const struct file_operations amfs_dir_fops = {
	.llseek = amfs_file_llseek,
	.read = generic_read_dir,
	.iterate = amfs_readdir,
	.unlocked_ioctl = amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = amfs_compat_ioctl,
#endif
	.open = amfs_open,
	.release = amfs_file_release,
	.flush = amfs_flush,
	.fsync = amfs_fsync,
	.fasync = amfs_fasync,
};
