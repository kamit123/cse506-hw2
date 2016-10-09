#ifndef AMFS_IOCTL_H
#define AMFS_IOCTL_H

struct amfs_patterns_info {
	char patterns[256][256];
	int count;
};

/* ioctl commands */
#define AMFS_IOCTL_GETPATTERNS          _IOR('x', 1, struct amfs_patterns *)
#define AMFS_IOCTL_ADDPATTERN           _IOW('x', 2, char *)
#define AMFS_IOCTL_REMOVEPATTERN        _IOR('x', 3, char *)

#endif
