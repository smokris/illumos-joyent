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
#include "preshared.h"
#include "worker.h"

typedef struct lockingfd {
	mutex_t lf_lock;
	int	lf_fd;
} lockingfd_t;

extern void pkt_init(void);
extern void pkt_fini(void);
extern void ikev2_sa_init(void);
extern void pfkey_init(void);
static void signal_init(void);
static void event(event_t, void *);
static void do_signal(int);
static void main_loop(void);

static void do_immediate(void);

static boolean_t done;
static thread_t signal_tid;

bunyan_logger_t *log = NULL;
int main_port = -1;

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

static int
nofail_cb(void)
{
	/*
	 * XXX Do we want to maybe change behavior based on debug/non-debug
	 * or make it a configuration or maybe SMF parameter to control
	 * abort vs. exit vs. something else?
	 */
	assfail("Out of memory", __FILE__, __LINE__);
	/*NOTREACHED*/
	return (UMEM_CALLBACK_EXIT(EXIT_FAILURE));
}

/*
 * For now at least, a workaround so that multiple bunyan children don't
 * step on each other during output be serializing writes to the same fd.
 */
static int
lockingfd_log(nvlist_t *nvl, const char *js, void *arg)
{
	lockingfd_t *lf = arg;
	int ret;

	mutex_enter(&lf->lf_lock);
	ret = bunyan_stream_fd(nvl, js, (void *)(uintptr_t)lf->lf_fd);
	mutex_exit(&lf->lf_lock);
	return (ret);
}

int
main(int argc, char **argv)
{
	FILE *f = NULL;
	char *cfgfile = "/etc/inet/ike/config";
	lockingfd_t logfd = { ERRORCHECKMUTEX, STDOUT_FILENO };
	int c, rc;
	boolean_t debug_mode = B_FALSE;
	boolean_t check_cfg = B_FALSE;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	umem_nofail_callback(nofail_cb);

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
		return (EXIT_FAILURE);
	}

	if ((rc = bunyan_init(basename(argv[0]), &log)) < 0)
		errx(EXIT_FAILURE, "bunyan_init() failed: %s", strerror(rc));

	/* hard coded to TRACE just during development */
	if ((rc = bunyan_stream_add(log, "stdout", BUNYAN_L_TRACE,
	    lockingfd_log, &logfd)) < 0) {
		errx(EXIT_FAILURE, "bunyan_stream_add() failed: %s",
		    strerror(rc));
	}

	if ((f = fopen(cfgfile, "rF")) == NULL) {
		STDERR(fatal, log, "cannot open config file",
		    BUNYAN_T_STRING, "filename", cfgfile);
		exit(EXIT_FAILURE);
	}

	process_config(f, check_cfg, log);

	(void) fclose(f);

	if (check_cfg)
		return (EXIT_SUCCESS);

	preshared_init(B_FALSE);

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

		if (close(fd) < 0) {
			STDERR(fatal, log, "close(2) failed",
			    BUNYAN_T_INT32, "fd", (int)fd,
			    BUNYAN_T_END);
			exit(EXIT_FAILURE);
		}
	}

	if ((main_port = port_create()) < 0) {
		STDERR(fatal, log, "main port_create() failed");
		exit(EXIT_FAILURE);
	}

	signal_init();
	pkcs11_init();
	pkt_init();
	ikev2_sa_init();

	/* XXX: make these configurable */
	worker_init(8);
	pfkey_init();
	inbound_init();
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
		config_rule_t *rule = cfg->cfg_rules[i];

		if (!rule->rule_immediate)
			continue;

		CONFIG_REFHOLD(cfg);	/* for worker */
		VERIFY(worker_send_cmd(WC_START, rule));
	}

	CONFIG_REFRELE(cfg);
}

static void
main_loop(void)
{
	port_event_t pe;

	(void) bunyan_trace(log, "starting main loop", BUNYAN_T_END);

	do_immediate();

	/*CONSTCOND*/
	while (!done) {
		char portsrc[PORT_SOURCE_STR_LEN];

		if (port_get(main_port, &pe, NULL) < 0) {
			STDERR(error, log, "port_get() failed");
			continue;
		}

		(void) bunyan_trace(log, "received event",
		    BUNYAN_T_STRING, "source",
		    port_source_str(pe.portev_source, portsrc,
		    sizeof (portsrc)),
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
	int signo;

	(void) bunyan_trace(log, "signal thread awaiting signals",
	    BUNYAN_T_END);

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

		if (port_send(main_port, EVENT_SIGNAL,
		    (void *)(uintptr_t)signo) < 0) {
			STDERR(error, log, "port_send() failed");
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

static void
signal_init(void)
{
	sigset_t nset;
	int rc;

	(void) bunyan_trace(log, "Creating signal handling thread",
	    BUNYAN_T_END);

	/* block all signals in main thread */
	(void) sigfillset(&nset);
	VERIFY0(thr_sigsetmask(SIG_SETMASK, &nset, NULL));

	rc = thr_create(NULL, 0, signal_thread, NULL, THR_DETACHED,
	    &signal_tid);
	if (rc != 0) {
		TSTDERR(rc, fatal, log,
		    "Signal handling thread creation failed");
		exit(EXIT_FAILURE);
	}
}
