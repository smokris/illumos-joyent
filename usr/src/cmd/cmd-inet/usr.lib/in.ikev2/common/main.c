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
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <bunyan.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <locale.h>
#include <libgen.h>
#include <netinet/in.h>
#include <port.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <thread.h>
#include <unistd.h>
#include "config.h"
#include "defs.h"
#include "defs.h"
#include "ikev2_sa.h"
#include "inbound.h"
#include "pkcs11.h"
#include "timer.h"
#include "worker.h"

extern void pkt_init(void);
extern void pkt_fini(void);
extern void ikev2_sa_init(void);
extern void random_init(void);
extern void pfkey_init(void);
static void signal_init(void);
static void event(event_t, void *);
static void do_signal(int);
static void main_loop(void);

static void do_immediate(void);

static boolean_t done;
static pthread_t signal_tid;

bunyan_logger_t *log = NULL;
int port = -1;

static void
usage(const char *name)
{
	(void) fprintf(stderr, "Usage: %s [-d] [-f cfgfile]\n"
	    "      %s -c [-f cfgfile]\n", name, name);
	exit(1);
}

#ifdef	DEBUG
const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
#else
const char *
_umem_debug_init(void)
{
	return ("guards");
}
#endif

int
main(int argc, char **argv)
{
	FILE *f = NULL;
	char *cfgfile = "/etc/inet/ike/config";
	int c, rc;
	boolean_t debug_mode = B_FALSE;
	boolean_t check_cfg = B_FALSE;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "cdf:")) != -1) {
		switch (c) {
		case 'd':
			debug_mode = B_TRUE;
			break;
		case 'c':
			check_cfg = B_TRUE;
			break;
		case 'f':
			cfgfile = optarg;
			break;
		case '?':
			(void) fprintf(stderr,
			    "Unrecognized option: -%c\n", optopt);
			usage(argv[0]);
			break;
		}
	}

	if (check_cfg && debug_mode) {
		(void) fprintf(stderr, "-d and -c options cannot both be "
		    "set\n");
		usage(argv[0]);
		return (1);
	}

	if ((rc = bunyan_init(basename(argv[0]), &log)) < 0)
		errx(EXIT_FAILURE, "bunyan_init() failed: %s", strerror(errno));

	/* hard coded just during development */
	if ((rc = bunyan_stream_add(log, "stdout", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)STDOUT_FILENO)) < 0)
		errx(EXIT_FAILURE, "bunyan_stream_add() failed: %s",
		    strerror(errno));

	if ((f = fopen(cfgfile, "rF")) == NULL) {
		STDERR(fatal, log, "cannot open config file",
		    BUNYAN_T_STRING, "filename", cfgfile);
		exit(EXIT_FAILURE);
	}

	process_config(f, check_cfg, log);

	(void) fclose(f);

	if (check_cfg)
		return (0);

	if (!debug_mode) {
		/* Explicitly handle closing of fds below */
		if (daemon(0, 1) != 0) {
			STDERR(fatal, log, "Could not run as daemon");
			exit(EXIT_FAILURE);
		}

		/*
		 * This assumes that STDERR_FILENO > STDOUT_FILENO &&
		 * STDERR_FILENO > STDIN_FILENO.  Since this has been the
		 * case for over 40 years, this seems a safe assumption.
		 */
		closefrom(STDERR_FILENO + 1);

		int fd = open("/dev/null", O_RDONLY);

		if (fd < 0) {
			STDERR(fatal, log,
			    "Could not open /dev/null for stdin");
			exit(EXIT_FAILURE);
		}

		if (dup2(fd, STDIN_FILENO) < 0) {
			STDERR(fatal, log,
			    "dup2 failed for stdin");
			exit(EXIT_FAILURE);
		}

		(void) close(fd);
	}

	if ((port = port_create()) < 0) {
		STDERR(fatal, log, "main port_create() failed");
		exit(EXIT_FAILURE);
	}

	if ((inbound_port = port_create()) < 0) {
		STDERR(fatal, log, "inbound port_create() failed");
		exit(EXIT_FAILURE);
	}

	signal_init();
	random_init();
	pkcs11_init();
	pkt_init();
	ike_timer_init();
	ikev2_sa_init();

	/* XXX: make these configurable */
	worker_init(8, 8);
	pfkey_init();
	inbound_init(2);
	main_loop();

	pkt_fini();
	pkcs11_fini();
	return (0);
}

/* Temp function to fire off IKE_SA_INIT exchanges */
static void
do_immediate(void)
{
	config_t *cfg = config_get();

	for (size_t i = 0; cfg->cfg_rules[i] != NULL; i++) {
		if (!cfg->cfg_rules[i]->rule_immediate)
			continue;

		config_rule_t *rule = cfg->cfg_rules[i];
		ikev2_sa_t *sa = NULL;
		struct sockaddr_storage laddr = { 0 };
		struct sockaddr_storage raddr = { 0 };
		sockaddr_u_t sl = { .sau_ss = &laddr };
		sockaddr_u_t sr = { .sau_ss = &raddr };

		VERIFY3S(rule->rule_local_addr[0].cfa_type, ==, CFG_ADDR_IPV4);
		VERIFY3S(rule->rule_remote_addr[0].cfa_type, ==, CFG_ADDR_IPV4);

		sl.sau_sin->sin_family = AF_INET;
		sl.sau_sin->sin_port = htons(IPPORT_IKE);
		(void) memcpy(&sl.sau_sin->sin_addr,
		    &rule->rule_local_addr[0].cfa_startu.cfa_ip4,
		    sizeof (in_addr_t));

		sr.sau_sin->sin_family = AF_INET;
		sr.sau_sin->sin_port = htons(IPPORT_IKE);
		(void) memcpy(&sr.sau_sin->sin_addr,
		    &rule->rule_remote_addr[0].cfa_startu.cfa_ip4,
		    sizeof (in_addr_t));

		sa = ikev2_sa_alloc(B_TRUE, NULL, &laddr, &raddr);
		VERIFY3P(sa, !=, NULL);

		bunyan_trace(sa->i2sa_log, "Dispatching larval SA to worker",
		    BUNYAN_T_STRING, "rule", rule->rule_label,
		    BUNYAN_T_END);

		worker_dispatch(WMSG_START, sa, I2SA_LOCAL_SPI(sa) % nworkers);
	}

	CONFIG_REFRELE(cfg);
}

static void
main_loop(void)
{
	port_event_t pe;
	int rc;

	(void) bunyan_trace(log, "starting main loop", BUNYAN_T_END);

	do_immediate();

	/*CONSTCOND*/
	while (!done) {
		if (port_get(port, &pe, NULL) < 0) {
			STDERR(error, log, "port_get() failed");
			continue;
		}

		(void) bunyan_trace(log, "received event",
		    BUNYAN_T_STRING, "source",
		    port_source_str(pe.portev_source),
		    BUNYAN_T_STRING, "event",
		    event_str(pe.portev_events),
		    BUNYAN_T_UINT32, "event num",
		    (int32_t)pe.portev_events,
		    BUNYAN_T_POINTER, "event arg", pe.portev_user,
		    BUNYAN_T_END);

		switch (pe.portev_source) {
		case PORT_SOURCE_USER:
			event(pe.portev_events, pe.portev_user);
			break;

		case PORT_SOURCE_ALERT:
			break;

		case PORT_SOURCE_TIMER: {
			void (*fn)(void) = (void (*)(void))pe.portev_user;
			fn();
			break;
		}
		default:
			INVALID("pe.portev_source");
		}
	}

	(void) bunyan_info(log, "Exiting", BUNYAN_T_END);
}

static void
event(event_t evt, void *arg)
{
	switch (evt) {
	case EVENT_NONE:
		return;
	case EVENT_SIGNAL:
		do_signal((int)(uintptr_t)arg);
		break;
	}
}

void
reload(void)
{
}

static void
do_signal(int signum)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		done = B_TRUE;
		break;
	case SIGHUP:
		reload();
		break;
	case SIGUSR1:
		(void) worker_add();
		break;
	case SIGUSR2:
		(void) worker_del();
		break;
	default:
		break;
	}
}

/*ARGSUSED*/
static void *
signal_thread(void *arg)
{
	char sigbuf[SIG2STR_MAX + 3]; /* add room for 'SIG' */
	sigset_t sigset;
	int signo, ret;

	bunyan_trace(log, "signal thread awaiting signals", BUNYAN_T_END);

	(void) sigfillset(&sigset);

	/*CONSTCOND*/
	while (1) {
		if (sigwait(&sigset, &signo) != 0) {
			STDERR(error, log, "sigwait() failed");
			continue;
		}

		(void) memset(sigbuf, 0, sizeof (sigbuf));
		(void) strlcat(sigbuf, "SIG", sizeof (sigbuf));
		sig2str(signo, sigbuf + 3);

		(void) bunyan_info(log, "signal received",
		    BUNYAN_T_STRING, "signal", sigbuf,
		    BUNYAN_T_INT32, "signum", (int32_t)signo,
		    BUNYAN_T_END);

		if (port_send(port, EVENT_SIGNAL, (void *)(uintptr_t)signo) < 0)
			STDERR(error, log, "port_send() failed");
	}

	/*NOTREACHED*/
	return (NULL);
}

static void
signal_init(void)
{
	pthread_attr_t attr;
	sigset_t nset;
	int rc;

	bunyan_trace(log, "Creating signal handling thread", BUNYAN_T_END);

	/* block all signals in main thread */
	(void) sigfillset(&nset);
	VERIFY0(thr_sigsetmask(SIG_SETMASK, &nset, NULL));

	rc = thr_create(NULL, 0, signal_thread, NULL, THR_DETACHED,
	    &signal_tid);
	if (rc != 0) {
		bunyan_fatal(log, "Signal handling thread creation failed",
		    BUNYAN_T_STRING, "errmsg", strerror(rc),
		    BUNYAN_T_INT32, "errno", (int32_t)rc,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", (int32_t)__LINE__,
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_END);
		exit(EXIT_FAILURE);
	}
}
