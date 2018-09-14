/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <inet/vxlnat.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VXLNATCONF	"/etc/inet/vxlnat.conf"

boolean_t	vxlnatd_debug_level = 0;
static char	vxlnatd_conffile[MAXPATHLEN];
static int	vxlnat_fd = -1;

/*
 * forward declarations
 */
static void vxlnatd_cleanup();

/*
 * Print the vxlnatd usage
 */
static void
usage(FILE *s)
{
	fprintf(s,
	    "Usage: vxlnatd [-fh]\n"
	    "\n"
	    "vxlnatd preforms NAT translation for a vxlan network\n"
	    "by leveraging the vxlnat kernel module.\n"
	    "\n"
	    "Options\n"
	    "  -d             set debug logging level\n"
	    "  -f             path to config file\n"
	    "  -h             print this message and exit\n");
}

/*
 * Read the configuration file and initialize with vxlnat
 */
static void
vxlnatd_initconf() {
	// open /dev/vxlnat
	if ((vxlnat_fd = open(VXLNAT_PATH, O_RDWR)) == -1) {
		fprintf(stderr, "failed to open %s: %s\n", VXLNAT_PATH,
			strerror(errno));
		exit(errno);
	}

	// send VXNM_VXLAN_ADDR
	if ((write(vxlnat_fd, (const void*)VXNM_VXLAN_ADDR,
		sizeof(VXNM_VXLAN_ADDR))) == -1) {
		fprintf(stderr, "failed write to  %s: %s\n", VXLNAT_PATH,
			strerror(errno));
		vxlnatd_cleanup();
		exit(errno);
	}


	// open/handle config file

}

/*
 * cleanup connection to /dev/vxlnat
 */
static void
vxlnatd_cleanup() {
	if (vxlnat_fd > 0) {
		close(vxlnat_fd);
	}

}

/*
 * vxlnatd common logging
 */
static void
vxlnatd_log() {

}

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	/*
	 * XXX KEBE SAYS:
	 *
	 * 1. Daemonize.
	 * 2. Have daemon open /dev/vxlnat.
	 * 3. Send flush message.
	 * 4. Read config file and send messages-per-line.
	 * 5. Sleep until signalled.
	 *	SIGHUP --> jump to step 3.
	 *	SIGINT (whatever ":kill" is) --> exit gracefully.
	 */


	int opt;

	(void) strlcpy(vxlnatd_conffile, VXLNATCONF, sizeof(vxlnatd_conffile));
	while ((opt = getopt(argc, argv, "d:f:h")) != -1) {
		switch (opt) {
		case 'd':
			/*
			 * TODO figure out debug log levels...
			 * Handle atoi error
			 */
			vxlnatd_debug_level = atoi(optarg);
			break;
		case 'f':
			(void) strlcpy(vxlnatd_conffile, optarg,
				sizeof(vxlnatd_conffile));
			break;
		case 'h':
			usage(stdout);
			return (0);
		default:
			usage(stderr);
			return (1);
		}
	}

	vxlnatd_initconf();

	/*
	 * XXX sleep until signaled
	 */
	while (1) {
		sleep(1);
	}

	vxlnatd_cleanup();
	return (1);
}
