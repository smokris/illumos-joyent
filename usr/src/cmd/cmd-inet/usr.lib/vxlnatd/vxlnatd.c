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
#include <bunyan.h>
#include <errno.h>
#include <fcntl.h>
#include <inet/vxlnat.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define	MAX_CONF_LINLEN	1000
#define	VXLNATCONF	"/etc/inet/vxlnat.conf"

const char *g_cmd = "vxlnatd";

bunyan_logger_t *vxlnatd_bunyan;
static char	vxlnatd_conffile[MAXPATHLEN];
static int	vxlnat_fd = -1;

/*
 * forward declarations
 */
static void vxlnatd_cleanup();
static void vxlnatd_bunyan_fini();
static void mac2str(uint8_t *mac, char *buf);

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
	    "  -d             turn on debug logging\n"
	    "  -f             path to config file\n"
	    "  -h             print this message and exit\n");
}

static vxn_msg_t *
alloc_empty_vxnm()
{
	vxn_msg_t *vxnm;

	if ((vxnm = (vxn_msg_t *)malloc(sizeof (vxn_msg_t))) == NULL) {
		(void) bunyan_fatal(vxlnatd_bunyan,
		    "failed to allocate vxn_msg_t",
		    BUNYAN_T_STRING, "message", strerror(errno),
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_END);
		(void) vxlnatd_cleanup();
		exit(EXIT_FAILURE);
	}

	bzero(vxnm, sizeof (vxn_msg_t));
	return (vxnm);
}

static void
log_vxnm(const char *log, vxn_msg_t *vxnm)
{
	char macstr[18];

	mac2str(vxnm->vxnm_ether_addr, macstr);

	(void) bunyan_trace(vxlnatd_bunyan,
	    log,
	    BUNYAN_T_UINT32, "type", vxnm->vxnm_type,
	    BUNYAN_T_UINT32, "vnetid", vxnm->vxnm_vnetid,
	    BUNYAN_T_UINT32, "prefix", vxnm->vxnm_prefix,
	    BUNYAN_T_UINT32, "vlanid", vxnm->vxnm_vlanid,
	    BUNYAN_T_STRING, "ether", macstr,
	    BUNYAN_T_IP6, "private", &vxnm->vxnm_private,
	    BUNYAN_T_IP6, "public", &vxnm->vxnm_public,
	    BUNYAN_T_END);
}

/*
 * Parse a IP string into a V4 mapped in6_addr.
 * Return -1 on failure, 4 for IPv4, and 6 for IPv6.
 */
static int
str2ip(struct in6_addr *ip, char *ipstr)
{

	if (inet_pton(AF_INET6, ipstr, ip) != 1) {
		uint32_t v4;
		if (inet_pton(AF_INET, ipstr, &v4) != 1) {
			(void) bunyan_error(vxlnatd_bunyan,
			    "failed to parse IP",
			    BUNYAN_T_END);
			return (-1);
		}
		IN6_IPADDR_TO_V4MAPPED(v4, ip);
		return (4);
	}

	return (6);
}

static void
mac2str(uint8_t *mac, char *buf)
{
	int i, n;
	n = sprintf(buf, "%02x", *mac++);
	for (i = 0; i < (ETHERADDRL - 1); i++)
		n += sprintf(buf+n, ":%02x", *mac++);
}

/*
 * XXX make this more robust!
 * currently ":412" will chop off high order bits and return ":12"
 */
static boolean_t
str2mac(char *buf, uint8_t *macaddr)
{
	return sscanf(buf, "%x:%x:%x:%x:%x:%x%c",
	    &macaddr[0],
	    &macaddr[1],
	    &macaddr[2],
	    &macaddr[3],
	    &macaddr[4],
	    &macaddr[5]) == 6 ? B_TRUE : B_FALSE;
}

static vxn_msg_t *
parse_bindaddr(char *line)
{
	char *ipstr;
	struct in6_addr bind;
	vxn_msg_t *vxnm;

	if ((ipstr = strtok(line, " \t\n")) == NULL)
		return (NULL);

	if (str2ip(&bind, ipstr) == -1)
		return (NULL);

	vxnm = alloc_empty_vxnm();

	vxnm->vxnm_type = VXNM_VXLAN_ADDR;
	vxnm->vxnm_private = bind;

	return (vxnm);
}

static vxn_msg_t *
parse_fixedentry(char *line)
{
	char *tok;
	int vnetid;
	struct in6_addr priv, pub;
	vxn_msg_t *vxnm;

	if ((tok = strtok(line, " \t\n")) == NULL)
		return (NULL);

	/*
	 * check for vnetid
	 * set errno to 0 in case vnetid is actually 0
	 */
	errno = 0;
	if ((vnetid = atoi(tok)) == 0) {
		if (errno != 0) {
			(void) bunyan_error(vxlnatd_bunyan,
			    "bad vnetid",
			    BUNYAN_T_STRING, "vnetid", tok,
			    BUNYAN_T_END);
			return (NULL);
		}
	}

	if ((tok = strtok(NULL, " \t\n")) == NULL)
		return (NULL);

	/* check for priv */
	if (str2ip(&priv, tok) == -1)
		return (NULL);

	if ((tok = strtok(NULL, " \t\n")) == NULL)
		return (NULL);

	/* check for pub */
	if (str2ip(&pub, tok) == -1)
		return (NULL);

	vxnm = alloc_empty_vxnm();

	vxnm->vxnm_type = VXNM_FIXEDIP;
	vxnm->vxnm_vnetid = vnetid;
	vxnm->vxnm_public = pub;
	vxnm->vxnm_private = priv;

	return (vxnm);
}

static vxn_msg_t *
parse_mapentry(char *line)
{
	/* type, pfx, vnetid, pub, priv, eth, vlanid */
	char *tok;
	int vnetid, vlanid, prefix, version;
	struct in6_addr priv, pub;
	uint8_t ether[ETHERADDRL];
	vxn_msg_t *vxnm;

	if ((tok = strtok(line, " \t\n")) == NULL)
		return (NULL);

	/*
	 * check for vnetid
	 * set errno to 0 in case vnetid is actually 0
	 */
	errno = 0;
	if ((vnetid = atoi(tok)) == 0) {
		if (errno != 0) {
			(void) bunyan_error(vxlnatd_bunyan,
			    "bad vnetid",
			    BUNYAN_T_STRING, "vnetid", tok,
			    BUNYAN_T_END);
			return (NULL);
		}
	}

	if ((tok = strtok(NULL, " \t\n")) == NULL)
		return (NULL);

	/* check for vlanid */
	errno = 0;
	if ((vlanid = atoi(tok)) == 0) {
		if (errno != 0 || vlanid < 0 || vlanid > 4096) {
			(void) bunyan_error(vxlnatd_bunyan,
			    "bad vlanid",
			    BUNYAN_T_STRING, "vlanid", tok,
			    BUNYAN_T_END);
			return (NULL);
		}
	}

	if ((tok = strtok(NULL, " \t\n")) == NULL)
		return (NULL);

	/* check for ether */
	if (!str2mac(tok, ether))
		return (NULL);

	if ((tok = strtok(NULL, "/")) == NULL)
		return (NULL);

	/* check for priv */
	if ((version = str2ip(&priv, tok)) == -1)
		return (NULL);


	if ((tok = strtok(NULL, " \t\n")) == NULL)
		return (NULL);

	/* check for prefix */
	errno = 0;
	if ((prefix = atoi(tok)) == 0) {
		if (errno != 0) {
			(void) bunyan_error(vxlnatd_bunyan,
			    "bad prefix",
			    BUNYAN_T_STRING, "prefix", tok,
			    BUNYAN_T_END);
			return (NULL);
		}
	}

	/* validate the prefix is within range */
	if (prefix < 0 || (version == 4 && prefix > 32) || prefix > 128) {
		(void) bunyan_error(vxlnatd_bunyan,
		    "invalid prefix",
		    BUNYAN_T_END);
		return (NULL);
	}

	if (version == 4)
		prefix += 96;


	if ((tok = strtok(NULL, " \t\n")) == NULL)
		return (NULL);

	/* check for pub */
	if (str2ip(&pub, tok) == -1)
		return (NULL);

	vxnm = alloc_empty_vxnm();

	vxnm->vxnm_type = VXNM_RULE;
	vxnm->vxnm_vnetid = vnetid;
	vxnm->vxnm_vlanid = vlanid;
	vxnm->vxnm_prefix = prefix;
	vxnm->vxnm_public = pub;
	vxnm->vxnm_private = priv;

	bcopy(ether, vxnm->vxnm_ether_addr, sizeof (ether));

	return (vxnm);
}


/*
 * Parse a single config file entry
 *
 * Returns NULL if we failed to parse the entry.
 * Otherwise the caller is responsible for freeing the returned vxn_msg_t
 */
static vxn_msg_t *
parse_confline(char *line)
{
	char *action, *lasts;

	if ((action = strtok_r(line, " \t\n", &lasts)) == NULL)
		return (NULL);

	if (strcmp(action, "bind") == 0)
		return (parse_bindaddr(lasts));

	if (strcmp(action, "fixed") == 0)
		return (parse_fixedentry(lasts));

	if (strcmp(action, "map") == 0)
		return (parse_mapentry(lasts));

	/* default action if we don't find a match */
	(void) bunyan_error(vxlnatd_bunyan,
	    "unknown action",
	    BUNYAN_T_STRING, "action", action,
	    BUNYAN_T_END);

	return (NULL);
}

/*
 * Read the configuration file and initialize with vxlnat
 */
static void
vxlnatd_initconf()
{
	char line[MAX_CONF_LINLEN];
	FILE *cfd;
	int i, entries = 0, lineno = 0;
	size_t arrsize = 32;
	vxn_msg_t *fvxnm;
	vxn_msg_t **msgs;

	/* open /dev/vxlnat if not already opened */
	if (vxlnat_fd == -1 && (vxlnat_fd = open(VXLNAT_PATH, O_RDWR)) == -1) {
		(void) bunyan_fatal(vxlnatd_bunyan,
		    "failed to open vxlnat device",
		    BUNYAN_T_STRING, "message", strerror(errno),
		    BUNYAN_T_STRING, "path", VXLNAT_PATH,
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_END);
		(void) vxlnatd_cleanup();
		exit(EXIT_FAILURE);
	}

	if ((cfd = fopen(vxlnatd_conffile, "r")) == NULL) {
		(void) bunyan_fatal(vxlnatd_bunyan,
		    "failed to open vxlnatd config",
		    BUNYAN_T_STRING, "message", strerror(errno),
		    BUNYAN_T_STRING, "path", vxlnatd_conffile,
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_END);
		(void) vxlnatd_cleanup();
		exit(EXIT_FAILURE);
	}

	if ((msgs = (vxn_msg_t **)malloc(arrsize * sizeof (vxn_msg_t *)))
	    == NULL) {
		(void) bunyan_fatal(vxlnatd_bunyan,
		    "failed to allocate vxnm array",
		    BUNYAN_T_STRING, "message", strerror(errno),
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_END);
		(void) vxlnatd_cleanup();
		exit(EXIT_FAILURE);
	}

	/* send a flush msg before anything else */
	fvxnm = alloc_empty_vxnm();
	fvxnm->vxnm_type = VXNM_FLUSH;
	msgs[entries] = fvxnm;
	entries++;

	while (fgets(line, sizeof (line), cfd) != NULL) {
		vxn_msg_t *vxnm;

		lineno++;

		/* skip empty lines */
		if (*line == '\n')
			continue;

		/* ignore lines that are comments */
		if (*line == '#')
			continue;

		/* error out if the line is too long */
		if (line[strlen(line) -1] != '\n') {
			(void) bunyan_error(vxlnatd_bunyan,
			    "config file line is too long",
			    BUNYAN_T_STRING, "path", vxlnatd_conffile,
			    BUNYAN_T_INT32, "line", lineno,
			    BUNYAN_T_END);
			(void) vxlnatd_cleanup();
			exit(EXIT_FAILURE);
		}

		/* attempt to parse the line into a vxn_msg_t */
		if ((vxnm = parse_confline(line)) == NULL) {
			(void) bunyan_fatal(vxlnatd_bunyan,
			    "failed to parse config file line",
			    BUNYAN_T_STRING, "path", vxlnatd_conffile,
			    BUNYAN_T_INT32, "line", lineno,
			    BUNYAN_T_END);
			(void) vxlnatd_cleanup();
			exit(EXIT_FAILURE);
		}

		/* double the size of the array if we are at max capacity */
		if (entries >= (arrsize - 1)) {
			arrsize = arrsize << 1;

			if ((msgs = (vxn_msg_t **)realloc(msgs,
			    arrsize * sizeof (vxn_msg_t *))) == NULL) {
				(void) bunyan_fatal(vxlnatd_bunyan,
				    "failed to allocate vxn_msg array",
				    BUNYAN_T_STRING, "message", strerror(errno),
				    BUNYAN_T_INT32, "errno", errno,
				    BUNYAN_T_END);
				(void) vxlnatd_cleanup();
				exit(EXIT_FAILURE);
			}
		}

		msgs[entries] = vxnm;
		entries++;
	}

	// send VXNM_VXLAN_ADDR
	for (i = 0; i < entries; i++) {
		(void) log_vxnm("writing vxn_msg_t to vxlnat device", msgs[i]);
		if ((write(vxlnat_fd, msgs[i],
		    sizeof (vxn_msg_t))) == -1) {
			(void) bunyan_fatal(vxlnatd_bunyan,
			    "failed to write to vxlnat device",
			    BUNYAN_T_STRING, "message", strerror(errno),
			    BUNYAN_T_INT32, "errno", errno,
			    BUNYAN_T_END);
			(void) vxlnatd_cleanup();
			exit(EXIT_FAILURE);
		}

		free(msgs[i]);
	}

	free(msgs);
}

/*
 * cleanup connection to /dev/vxlnat
 */
static void
vxlnatd_cleanup()
{
	if (vxlnat_fd > 0) {
		close(vxlnat_fd);
	}
	vxlnatd_bunyan_fini();
}

/*
 * vxlnatd bunyan logging
 */
static int
vxlnatd_bunyan_init(int level)
{
	int ret;

	if ((ret = bunyan_init("vxlnatd", &vxlnatd_bunyan)) != 0)
		return (ret);
	ret = bunyan_stream_add(vxlnatd_bunyan, "stderr", level,
	    bunyan_stream_fd, (void *)STDERR_FILENO);
	if (ret != 0)
		(void) vxlnatd_bunyan_fini();
	return (ret);
}

static void
vxlnatd_bunyan_fini(void)
{
	if (vxlnatd_bunyan != NULL)
		bunyan_fini(vxlnatd_bunyan);
}

void
signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		(void) bunyan_info(vxlnatd_bunyan,
		    "reloading configuration",
		    BUNYAN_T_END);
		vxlnatd_initconf();
		break;
	case SIGINT:
		(void) bunyan_info(vxlnatd_bunyan,
		    "exiting...",
		    BUNYAN_T_END);
		(void) vxlnatd_cleanup();
		exit(EXIT_SUCCESS);
		break;
	case SIGALRM:
		break;
	default:
		(void) bunyan_fatal(vxlnatd_bunyan,
		    "caught unknown signal",
		    BUNYAN_T_INT32, "signal", sig,
		    BUNYAN_T_END);
		(void) vxlnatd_cleanup();
		exit(EXIT_FAILURE);
	}
}

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	/*
	 * XXX Todo:
	 *
	 * 1. Daemonize.
	 *
	 */


	int opt;
	int vxlnatd_debug_level;
	int d_flag = 0;
	struct sigaction act;

	(void) strlcpy(vxlnatd_conffile, VXLNATCONF, sizeof (vxlnatd_conffile));
	while ((opt = getopt(argc, argv, "df:h")) != -1) {
		switch (opt) {
		case 'd':
			d_flag++;
			break;
		case 'f':
			(void) strlcpy(vxlnatd_conffile, optarg,
			    sizeof (vxlnatd_conffile));
			break;
		case 'h':
			usage(stdout);
			return (0);
		default:
			usage(stderr);
			return (1);
		}
	}

	vxlnatd_debug_level = (d_flag > 0) ? BUNYAN_L_TRACE : BUNYAN_L_INFO;
	if (vxlnatd_bunyan_init(vxlnatd_debug_level) != 0)
		fprintf(stderr, "failed to setup bunyan logger\n");

	vxlnatd_initconf();

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = signal_handler;
	(void) sigaction(SIGHUP, &act, NULL); /* flush; reload config */
	(void) sigaction(SIGINT, &act, NULL); /* exit */

	for (;;) {
		/* sleep until signaled */
		(void) sigsuspend(&act.sa_mask);
	}
}
