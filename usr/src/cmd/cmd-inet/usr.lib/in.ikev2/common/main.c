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
 * Copyright 2017 Joyent, Inc.
 */

#include <pthread.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <port.h>
#include <bunyan.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <locale.h>
#include <ucontext.h>
#include "pkcs11.h"
#include "defs.h"
#include "timer.h"
#include "worker.h"
#include "config.h"

extern void pkt_init(void);
extern void pkt_fini(void);
extern void ikev2_sa_init(void);
extern void random_init(void);
extern void pfkey_init(void);

static void signal_init(void);
static void event(event_t, void *);
static void do_signal(int);
static void main_loop(void);

static const char *port_source_str(ushort_t);
static const char *event_str(event_t);

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

	if ((port = port_create()) < 0)
		STDERR(fatal, log, "port_create() failed");

	signal_init();
	random_init();
	pkcs11_init();
	pkt_init();
	ike_timer_init();
	pfkey_init();

	/* XXX: make these configurable */
	worker_init(8, 8);

	main_loop();

	pkt_fini();
	pkcs11_fini();

	return (0);
}

static void
main_loop(void)
{
	port_event_t pe;
	int rc;

	(void) bunyan_trace(log, "starting main loop", BUNYAN_T_END);

	/*CONSTCOND*/
	while (!done) {
		if (port_get(port, &pe, NULL) < 0) {
			STDERR(error, log, "port_get() failed");
			continue;
		}

		switch (pe.portev_source) {
		case PORT_SOURCE_USER:
			(void) bunyan_trace(log, "received event",
			    BUNYAN_T_STRING, "source",
			    port_source_str(pe.portev_source),
			    BUNYAN_T_UINT32, "source val",
			    (uint32_t)pe.portev_events,
			    BUNYAN_T_STRING, "event",
			    event_str(pe.portev_events),
			    BUNYAN_T_UINT32, "event num",
			    (int32_t)pe.portev_events,
			    BUNYAN_T_POINTER, "event arg", pe.portev_user,
			    BUNYAN_T_END);
			event(pe.portev_events, pe.portev_user);
			break;

		case PORT_SOURCE_FD: {
			char buf[128] = { 0 };
			(void) addrtosymstr(pe.portev_user, buf, sizeof (buf));

			(void) bunyan_trace(log, "received event",
			    BUNYAN_T_STRING, "source",
			    port_source_str(pe.portev_source),
			    BUNYAN_T_UINT32, "source val",
			    (uint32_t)pe.portev_events,
			    BUNYAN_T_INT32, "fd", (int32_t)pe.portev_object,
			    BUNYAN_T_STRING, "cb", buf,
			    BUNYAN_T_POINTER, "cbval", pe.portev_user,
			    BUNYAN_T_END);

			void (*fn)(int) = (void (*)(int))pe.portev_user;
			int fd = (int)pe.portev_object;
			fn(fd);
			break;
		}

		case PORT_SOURCE_ALERT:
			(void) bunyan_trace(log, "received event",
			    BUNYAN_T_STRING, "source",
			    port_source_str(pe.portev_source),
			    BUNYAN_T_UINT32, "source val",
			    (uint32_t)pe.portev_events,
			    BUNYAN_T_END);
			break;

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

void
schedule_socket(int fd, void (*cb)(int, void *))
{
	if (port_associate(port, PORT_SOURCE_FD, fd, POLLIN, cb) < 0)
		STDERR(error, log, "port_associate() failed");
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

	bunyan_trace(log, "signal_init() enter", BUNYAN_T_END);

	/* block all signals in main thread */
	(void) sigfillset(&nset);
	(void) pthread_sigmask(SIG_SETMASK, &nset, NULL);

	PTH(pthread_attr_init(&attr));
	PTH(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));
	PTH(pthread_create(&signal_tid, &attr, signal_thread, NULL));
	PTH(pthread_attr_destroy(&attr));

	bunyan_trace(log, "signal_init() exit", BUNYAN_T_END);
}

static const char *
port_source_str(ushort_t src)
{
#define	STR(x) case x: return (#x)

	switch (src) {
	STR(PORT_SOURCE_AIO);
	STR(PORT_SOURCE_FD);
	STR(PORT_SOURCE_MQ);
	STR(PORT_SOURCE_TIMER);
	STR(PORT_SOURCE_USER);
	STR(PORT_SOURCE_ALERT);
	STR(PORT_SOURCE_FILE);
	default:
		return ("UNKNOWN");
	}
#undef STR
}

static const char *
event_str(event_t evt)
{
#define	STR(x) case x: return (#x)

	switch (evt) {
	STR(EVENT_NONE);
	STR(EVENT_SIGNAL);
	default:
		return ("UNKNOWN");
	}
}

bunyan_logfn_t
getlog(bunyan_level_t level)
{
	switch (level) {
	case BUNYAN_L_TRACE:
		return (bunyan_trace);
	case BUNYAN_L_DEBUG:
		return (bunyan_debug);
	case BUNYAN_L_INFO:
		return (bunyan_info);
	case BUNYAN_L_WARN:
		return (bunyan_warn);
	case BUNYAN_L_ERROR:
		return (bunyan_error);
	case BUNYAN_L_FATAL:
		return (bunyan_fatal);
        }

	return (NULL);
}

extern uint32_t ss_port(const struct sockaddr_storage *);
extern const void *ss_addr(const struct sockaddr_storage *);
extern int ss_bunyan(const struct sockaddr_storage *);
