#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "amfs_ioctl.h"

enum actions {listp, addp, removep};

int main(int argc, char *const argv[])
{
	extern char *optarg;
        extern int optind;
	int c, err = 0, fd, i;
	enum actions action = -1;
	char *pattern, *mount_point;
	struct amfs_patterns_info *patterns_info = NULL;

	while((c = getopt(argc, argv, "la:r:")) != -1){
                switch(c){
			case 'l':
				if (action != -1){
					printf("Only one operating allowed, list, add or remove\n");
					err = -1;
					goto out;
				}
				action = listp;
				break;

			case 'a':
				if (action != -1){
                                        printf("Only one operating allowed, list, add or remove\n");
					err = -1;
                                        goto out;
                                }
                                action = addp;
				pattern = argv[optind - 1];
				break;

			case 'r':
                                if (action != -1){
                                        printf("Only one operating allowed, list, add or remove\n");
					err = -1;
                                        goto out;
                                }
                                action = removep;
				pattern = argv[optind - 1];
				break;

			default:
				printf("Unsupported option: %c\n", c);
				err = -1;
				goto out;
		}
	}

	/* Making sure mount point is present */
        if(optind+1 > argc){
                printf("missing parameters\n");
		err = -1;
                goto out;
        }
	mount_point = argv[optind];

	fd = open(mount_point, O_RDONLY);
	if (fd == -1){
		printf("mount point does not exist\n");
		err = -1;
		goto out;
	}

	switch (action){
		case listp:
			patterns_info = malloc(sizeof(struct amfs_patterns_info));
			if(ioctl(fd, AMFS_IOCTL_GETPATTERNS, patterns_info) == -1){
				printf("error getting patterns (errno = %d)\n", errno);
				err = -1;
				goto out;
			}

			for (i=0; i<patterns_info->count; ++i){
				printf("%s\n", patterns_info->patterns[i]);
			}
			break;

		case addp:
			if(ioctl(fd, AMFS_IOCTL_ADDPATTERN, pattern) == -1){
				printf("error adding patterns (errno = %d)\n", errno);
				err = -1;
				goto out;
			}
			break;

		case removep:
                        if(ioctl(fd, AMFS_IOCTL_REMOVEPATTERN, pattern) == -1){
                                printf("error removing pattern (errno = %d)\n", errno);
				err = -1;
                                goto out;
                        }
                        break;
	}

	perror ("Result of ioctl");
out:
	close(fd);
	free(patterns_info);
	
	return err;
}
