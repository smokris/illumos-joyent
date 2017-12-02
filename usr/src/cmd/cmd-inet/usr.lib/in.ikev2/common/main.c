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
#include <paths.h>
#include <port.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread.h>
#include <unistd.h>
#include "config.h"
#include "defs.h"
#include "defs.h"
#include "ikev2_cookie.h"
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
extern void pfkey_init(void);
static void signal_init(void);
static void event(event_t, void *);
static void do_signal(int);
static void main_loop(int);
static int ikev2_daemonize(void);

static void do_immediate(void);

static boolean_t done;
static thread_t signal_tid;

__thread bunyan_logger_t *log = NULL;
bunyan_logger_t *main_log = NULL;
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
	 * XXX Do we want to control behavior (abort vs exit) based on
	 * debug/non-debug, or configuration or SMF parameter?
	 */
	assfail("Out of memory", __FILE__, __LINE__);
	/*NOTREACHED*/
	return (UMEM_CALLBACK_EXIT(EXIT_FAILURE));
}

/*
 * A temporary workaround to serialize writing to the same fd by multiple
 * bunyan children
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
	struct rlimit rlim;
	int c, rc;
	int fd = -1;
	boolean_t debug_mode = B_FALSE;
	boolean_t check_cfg = B_FALSE;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	umem_nofail_callback(nofail_cb);

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_CORE, &rlim);

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
	main_log = log;

	if ((f = fopen(cfgfile, "rF")) == NULL) {
		STDERR(fatal, "cannot open config file",
		    BUNYAN_T_STRING, "filename", cfgfile);
		exit(EXIT_FAILURE);
	}

	process_config(f, check_cfg);

	if (fclose(f) == EOF)
		err(EXIT_FAILURE, "fclose(\"%s\") failed", cfgfile);

	if (check_cfg)
		return (EXIT_SUCCESS);

	preshared_init(B_FALSE);

	if (!debug_mode)
		fd = ikev2_daemonize();

	if ((main_port = port_create()) < 0) {
		STDERR(fatal, "main port_create() failed");
		exit(EXIT_FAILURE);
	}

	signal_init();
	pkcs11_init();
	pkt_init();
	ikev2_sa_init();

	/* XXX: make these configurable */
	worker_init(8);
	pfkey_init();
	ikev2_cookie_init();
	inbound_init();
	main_loop(fd);

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
main_loop(int fd)
{
	port_event_t pe;
	int rval = 0;

	(void) write(fd, &rval, sizeof (rval));
	(void) close(fd);

	(void) bunyan_trace(log, "starting main loop", BUNYAN_T_END);

	do_immediate();

	/*CONSTCOND*/
	while (!done) {
		if (port_get(main_port, &pe, NULL) < 0) {
			STDERR(error, "port_get() failed");
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
			INVALID(pe.portev_source);
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

static int
ikev2_daemonize(void)
{
	sigset_t set, oset;
	pid_t child;
	int dupfd, fds[2];

	if (chdir("/") != 0)
		err(EXIT_FAILURE, "chdir(\"/\") failed");

	closefrom(STDERR_FILENO + 1);

	if (pipe(fds) != 0)
		err(EXIT_FAILURE, "Could not create pipe for daemonizing");

	/*
	 * Block everything except SIGABRT until the child is up and running
	 * so the parent doesn't accidentially exit too soon.
	 */
	if (sigfillset(&set) != 0)
		abort();
	if (sigdelset(&set, SIGABRT) != 0)
		abort();
	if (thr_sigsetmask(SIG_SETMASK, &set, &oset) != 0)
		abort();

	if ((child = fork()) == -1)
		err(EXIT_FAILURE, "Could not fork for daemonizing");

	if (child != 0) {
		int status;

		(void) close(fds[1]);
		if (read(fds[0], &status, sizeof (status)) == sizeof (status))
			_exit(status);

		if (waitpid(child, &status, 0) == child && WIFEXITED(status))
			_exit(WEXITSTATUS(status));

		_exit(EXIT_FAILURE);
	}

	/* XXX: Drop privileges */

	if (close(fds[0]) != 0)
		abort();
	if (setsid() == -1)
		abort();
	if (thr_sigsetmask(SIG_SETMASK, &oset, NULL) != 0)
		abort();

	(void) umask(0022);

	if ((dupfd = open(_PATH_DEVNULL, O_RDONLY)) < 0)
		err(EXIT_FAILURE, "Could not open %s", _PATH_DEVNULL);
	if (dup2(dupfd, STDIN_FILENO) == -1)
		err(EXIT_FAILURE, "Could not dup stdin");

	return (fds[1]);
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

	log = arg;

	(void) bunyan_trace(log, "signal thread awaiting signals",
	    BUNYAN_T_END);

	if (sigfillset(&sigset) != 0)
		abort();
	if (sigdelset(&sigset, SIGABRT) != 0)
		abort();

	/*CONSTCOND*/
	while (1) {
		if (sigwait(&sigset, &signo) != 0) {
			STDERR(error, "sigwait() failed");
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
			STDERR(error, "port_send() failed");
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

static void
signal_init(void)
{
	bunyan_logger_t *child = NULL;
	sigset_t nset;
	int rc;

	if (bunyan_child(log, &child, BUNYAN_T_END) != 0)
		err(EXIT_FAILURE, "Cannot create signal thread logger");

	(void) bunyan_trace(log, "Creating signal handling thread",
	    BUNYAN_T_END);

	/* block all signals in main thread */
	if (sigfillset(&nset) != 0)
		abort();
	if (sigdelset(&nset, SIGABRT) != 0)
		abort();

	VERIFY0(thr_sigsetmask(SIG_SETMASK, &nset, NULL));

	rc = thr_create(NULL, 0, signal_thread, child, THR_DETACHED,
	    &signal_tid);
	if (rc != 0) {
		TSTDERR(rc, fatal,
		    "Signal handling thread creation failed");
		exit(EXIT_FAILURE);
	}
}
