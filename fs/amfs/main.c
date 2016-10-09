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
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/string.h>
#include <linux/list.h>

enum { amfs_opt_pattdb, amfs_opt_err };

static const match_table_t tokens = {
	{amfs_opt_pattdb, "pattdb=%s"},
	{amfs_opt_err, NULL}
};

struct amfs_mount_data {
	void *lower_path_name;
	void *raw_data;
};

static int add_pattern(struct list_head *patt_list, char *buf)
{
	char *token;
	struct amfs_virus_pattern *patt;
	int err = 0;

	while (buf != NULL) {
		token = strsep(&buf, "\n");
		if (token == NULL || strlen(token) == 0)
			continue;

		patt =
		    kmalloc(sizeof(struct amfs_virus_pattern), GFP_KERNEL);
		if (patt == NULL) {
			printk(KERN_ERR "error while kmalloc for patt\n");
			err = -ENOMEM;
			goto out;
		}

		patt->pattern = token;
		list_add(&patt->patt_list, patt_list);
	}
out:
	return err;
}

static int is_regular(char *src)
{
	mm_segment_t fs;
	int ret = 1;
	struct kstat stat;

	fs = get_fs();
	set_fs(get_ds());
	ret = vfs_stat(src, &stat);
	if (ret) {
		printk(KERN_ERR "error in is_regular while vfs_stat\n");
		set_fs(fs);
		goto out;
	}
	set_fs(fs);

	if (!S_ISREG(stat.mode))
		ret = 0;

out:
	return ret;
}

static int amfs_read_pattdb(struct super_block *sb)
{
	int err = 0, size_read;
	struct amfs_sb_info *sbi;
	struct file *pattdb = NULL;
	mm_segment_t fs = get_fs();
	char *buf, *last;

	sbi = AMFS_SB(sb);
	if (!sbi->pattdb_src) {
		err = -EINVAL;
		goto out;
	}

	err = is_regular(sbi->pattdb_src);
	if (err) {
		printk(KERN_ERR
		       "pattdb is not a regular file or error checking\n");
		err = -EINVAL;
		goto out;
	}

	pattdb = filp_open(sbi->pattdb_src, O_RDONLY, 0);
	if (IS_ERR(pattdb)) {
		printk("KERN_ERR error opening pattdb\n");
		err = PTR_ERR(pattdb);
		goto out;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		printk(KERN_ERR "error while kmalloc for buf\n");
		err = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&sbi->patt_list);
	set_fs(get_ds());
	while ((size_read =
		pattdb->f_op->read(pattdb, buf, PAGE_SIZE,
				   &pattdb->f_pos)) > 0) {
		if (size_read < PAGE_SIZE) {
			memcpy(&buf[size_read], "\0", 1);
		} else {
			last = strrchr(buf, '\n');
			if (last == NULL) {
				err = -EINVAL;
				goto out;
			}
			last[0] = '\0';
			pattdb->f_op->llseek(pattdb,
					     -((buf + (size_read - 1)) -
					       last), SEEK_CUR);
		}

		err = add_pattern(&sbi->patt_list, buf);
		if (err) {
			printk(KERN_ERR "error adding pattern to list\n");
			goto out;
		}

		buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (buf == NULL) {
			printk(KERN_ERR
			       "error while kmalloc for buf while reading\n");
			err = -ENOMEM;
			goto out;
		}
	}
	sbi->version = get_seconds();

out:
	set_fs(fs);
	if (pattdb != NULL)
		filp_close(pattdb, NULL);
	return err;
}

static int amfs_parse_options(struct super_block *sb, char *options)
{
	int rc = 0;
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int token;

	if (!options) {
		rc = -EINVAL;
		goto out;
	}

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case amfs_opt_pattdb:
			amfs_set_pattdb_src(sb, args[0].from);
			break;
		default:
			printk(KERN_ERR "unsupported mount options\n");
			rc = -EINVAL;
			goto out;
		}
	}

out:
	if (rc)
		AMFS_SB(sb)->pattdb_src = NULL;
	return rc;
}

/*
 * There is no need to lock the amfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int amfs_read_super(struct super_block *sb, void *raw_data,
			   int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	struct inode *inode;
	struct amfs_mount_data *mount_data =
	    (struct amfs_mount_data *) raw_data;
	char *dev_name = (char *) mount_data->lower_path_name;

	if (!dev_name) {
		printk(KERN_ERR
		       "amfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR "amfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kmalloc(sizeof(struct amfs_sb_info), GFP_KERNEL);
	if (!AMFS_SB(sb)) {
		printk(KERN_CRIT "amfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	err = amfs_parse_options(sb, mount_data->raw_data);
	if (err) {
		printk("error in parse options\n");
		goto out_freepatt;
	}

	err = amfs_read_pattdb(sb);
	if (err) {
		printk("error while reading pattdb\n");
		goto out_freepatt;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	amfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &amfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = amfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &amfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	amfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "amfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out;		/* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
out_freepatt:
	kfree(AMFS_SB(sb)->pattdb_src);
	kfree(AMFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

struct dentry *amfs_mount(struct file_system_type *fs_type, int flags,
			  const char *dev_name, void *raw_data)
{
	struct dentry *d;
	void *lower_path_name = (void *) dev_name;
	struct amfs_mount_data mount_data = {
		.lower_path_name = lower_path_name,
		.raw_data = raw_data
	};

	d = mount_nodev(fs_type, flags, &mount_data, amfs_read_super);

	return d;
}

static void amfs_kill_block_super(struct super_block *sb)
{
	struct amfs_virus_pattern *pos, *temp;
	struct amfs_sb_info *sbi = (struct amfs_sb_info *) sb->s_fs_info;
	int c = 0;
	kill_anon_super(sb);


	if (sbi != NULL) {
		kfree(sbi->pattdb_src);

		list_for_each_entry_safe(pos, temp, &sbi->patt_list,
					 patt_list) {
			list_del(&pos->patt_list);

			if (c == 0) {
				kfree(pos->pattern);
				c = 1;
			}
			kfree(pos);
		}
	}

	return;
}

static struct file_system_type amfs_fs_type = {
	.owner = THIS_MODULE,
	.name = AMFS_NAME,
	.mount = amfs_mount,
	.kill_sb = amfs_kill_block_super,
	.fs_flags = 0,
};

MODULE_ALIAS_FS(AMFS_NAME);

static int __init init_amfs_fs(void)
{
	int err;

	pr_info("Registering amfs " AMFS_VERSION "\n");

	err = amfs_init_inode_cache();
	if (err)
		goto out;
	err = amfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&amfs_fs_type);
out:
	if (err) {
		amfs_destroy_inode_cache();
		amfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_amfs_fs(void)
{
	amfs_destroy_inode_cache();
	amfs_destroy_dentry_cache();
	unregister_filesystem(&amfs_fs_type);
	pr_info("Completed amfs module unload\n");
}

MODULE_AUTHOR
    ("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
     " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Amfs " AMFS_VERSION " (http://amfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_amfs_fs);
module_exit(exit_amfs_fs);
