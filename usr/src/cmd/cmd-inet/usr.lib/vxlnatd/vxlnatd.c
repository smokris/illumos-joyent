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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inet/vxlnat.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <unistd.h>

#define MAX_CONF_LINLEN	1000
#define VXLNATCONF	"/etc/inet/vxlnat.conf"

const char *g_cmd = "vxlnatd";

boolean_t	vxlnatd_debug_level = 0;
static char	vxlnatd_conffile[MAXPATHLEN];
static int	vxlnat_fd = -1;

/*
 * forward declarations
 */
static void vxlnatd_cleanup();
#ifdef notyet
static void vxlnatd_log();
#endif

/*
 * Print the vxlnatd usage
 */
static void
usage(FILE *s)
{
	fprintf(s,
	    "Usage: vxlnatd [-dfh]\n"
	    "\n"
	    "vxlnatd preforms NAT translation for a vxlan network\n"
	    "by leveraging the vxlnat kernel module.\n"
	    "\n"
	    "Options\n"
	    "  -d             set debug logging level\n"
	    "  -f             path to config file\n"
	    "  -h             print this message and exit\n");
}

static void
fatal(char *fmt, ...)
{
	va_list ap;
	int error = errno;

	va_start(ap, fmt);

	(void) fprintf(stderr, "%s: ", g_cmd);
	/*LINTED*/
	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n", strerror(error));

	vxlnatd_cleanup();

	exit(EXIT_FAILURE);
}

static int
parse_ip(struct in6_addr *ip, char *ipstr)
{

	if (inet_pton(AF_INET6, ipstr, ip) != 1) {
                uint32_t v4;
                if (inet_pton(AF_INET, ipstr, &v4) != 1) {
                        return (-1);
                }
                IN6_IPADDR_TO_V4MAPPED(v4, ip);
        }

	return (0);
}

static vxn_msg_t *
parse_bindaddr(char *line)
{
	char *ipstr;
	struct in6_addr bind;
	vxn_msg_t *vxnm;

	if ((ipstr = strtok(line, " \t\n")) == NULL)
		return (NULL);

	if (parse_ip(&bind, ipstr) == -1)
		return (NULL);

	if ((vxnm = (vxn_msg_t *)malloc(sizeof(vxn_msg_t))) == NULL)
		fatal("failed to allocate vxnm");

	bzero(vxnm, sizeof(vxn_msg_t));

	vxnm->vxnm_type = VXNM_VXLAN_ADDR;
	vxnm->vxnm_private = bind;

	return (vxnm);
}


/*
 * Parse a single config file entry
 *
 * Returns NULL if we failed to parse the entry.
 * Otherwise the caller is responsible for freeing the returned vxn_msg_t
 */
static vxn_msg_t *
parse_confline(char* line)
{
	char *action, *lasts;

	if ((action = strtok_r(line, " \t\n", &lasts)) == NULL)
		return (NULL);

	if (strcmp(action, "bind") == 0)
		return parse_bindaddr(lasts);

	/* Add other actions here */

	/* default action if we don't find a match */
	return (NULL);
}

/*
 * Read the configuration file and initialize with vxlnat
 */
static void
vxlnatd_initconf() {
	char line[MAX_CONF_LINLEN];
	FILE *cfd;
	int i, entries = 0, lineno = 0;
	size_t arrsize = 32;
	vxn_msg_t **msgs;

	// open /dev/vxlnat
	if ((vxlnat_fd = open(VXLNAT_PATH, O_RDWR)) == -1)
		fatal("failed to open %s", VXLNAT_PATH);

	if ((cfd = fopen(vxlnatd_conffile, "r")) == NULL)
		fatal("failed to open %s", vxlnatd_conffile);

	if ((msgs = (vxn_msg_t **)malloc(arrsize * sizeof(vxn_msg_t *)))
		== NULL)
		fatal("failed to allocate vxn_msg array");

	while(fgets(line, sizeof(line), cfd) != NULL) {
		vxn_msg_t *vxnm;

		lineno++;

		/* skip empty lines */
		if (*line == '\n')
			continue;

		/* ignore lines that are comments */
		if (*line == '#')
			continue;

		/* error out if the line is too long */
		if (line[strlen(line) -1] != '\n')
			fatal("line %d is too long\n", lineno);

		/* attempt to parse the line into a vxn_msg_t */
		if ((vxnm = parse_confline(line)) == NULL)
			fatal("failed to parse config %s at line %d\n",
				vxlnatd_conffile, lineno);

		/* double the size of the array if we are at max capacity*/
		if (entries >= (arrsize - 1)) {
			arrsize = arrsize << 1;

			if ((msgs = (vxn_msg_t **)realloc(msgs,
				arrsize * sizeof(vxn_msg_t *))) == NULL)
				fatal("failed to allocate vxn_msg array");
		}

		msgs[entries] = vxnm;
		entries++;
	}

	// send VXNM_VXLAN_ADDR
	for (i = 0; i < entries; i++) {
		if ((write(vxlnat_fd, msgs[i],
			sizeof(vxn_msg_t))) == -1)
			fatal("failed to write to %s", VXLNAT_PATH);

		free(msgs[i]);
	}

	free(msgs);
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

#ifdef notyet
/*
 * vxlnatd common logging
 */
static void
vxlnatd_log() {

}
#endif

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
