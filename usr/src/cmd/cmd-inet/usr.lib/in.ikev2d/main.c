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
#include <libscf.h>
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
#include "util.h"
#include "worker.h"

typedef struct lockingfd {
	mutex_t lf_lock;
	int	lf_fd;
} lockingfd_t;

extern void pkt_init(void);
extern void pkt_fini(void);
extern void pfkey_init(void);
extern void ikev2_door_init(const char *);

static void signal_init(void);
static void event(event_t, void *);
static void do_signal(int);
static void main_loop(int);
static int ikev2_daemonize(void);

static void do_immediate(void);
static void load_smf_config(void);

/*
 * The location of the configuration file, dynamically allocated to simplify
 * interfacing with smf(5)
 */
static char *configfile;

static thread_t signal_tid;
static boolean_t done;

/* Required for libipsecutils */
extern char *my_fmri;

__thread bunyan_logger_t *log = NULL;
bunyan_logger_t *main_log = NULL;
uint32_t category = UINT32_MAX;
int main_port = -1;

lockingfd_t fdlock = {
    .lf_lock = ERRORCHECKMUTEX,
    .lf_fd = STDOUT_FILENO
};

static struct scf_cfg {
	const char	*sc_name;
	scf_type_t	sc_type;
	void		*sc_val;
} scf_cfg[] = {
	{ "configfile", SCF_TYPE_ASTRING, &configfile },
	{ "workers", SCF_TYPE_COUNT, &wk_initial_nworkers },
};

/*
 * XXX: Both ipseckey(1M) and ikeadm(1M) have the ability to show actual key
 * values.  in.iked(1M) also has the notion of a privilege level (not to
 * be confused with privileges(5)) where one can prevent it from ever disclosing
 * key material and to change the setting requires a restart.  We'll probably
 * want similar functionality and this setting will get weaved into that.
 */
boolean_t show_keys = B_TRUE; /* XXX XXX Change before putback! */

static void
usage(const char *name)
{
	(void) fprintf(stderr, "Usage: %s [-d] [-f cfgfile]\n"
	    "      %s -c [-f cfgfile]\n", name, name);
	exit(1);
}

#ifndef lint
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
#endif /* lint */

static int
nofail_cb(void)
{
	/*
	 * XXX Do we want to control behavior (abort vs exit) based on
	 * debug/non-debug, configuration or a SMF parameter?
	 *
	 * In general, we try to recover or just abort the specific operation
	 * we're attempting if we cannot allocate memory and let everything else
	 * continue as much as we can (saving the nofail allocations largely for
	 * startup).  It may be more desirable to exit or abort and let SMF
	 * try to recover things if we get to this point (subject to sanity
	 * checks -- e.g. that we're not allowing a remote peer to get us
	 * to allocate 1Tb of ram, etc.).
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
	uint32_t cval = 0;
	int ret;

	if (nvlist_lookup_uint32(nvl, LOG_KEY_CATEGORY, &cval) == 0 &&
	    (cval & category) == 0)
		return (0);

	mutex_enter(&lf->lf_lock);
	ret = bunyan_stream_fd(nvl, js, (void *)(uintptr_t)lf->lf_fd);
	mutex_exit(&lf->lf_lock);
	return (ret);
}

int
main(int argc, char **argv)
{
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

	configfile = ustrdup(CONFIG_FILE, UMEM_NOFAIL);

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_CORE, &rlim);

	my_fmri = getenv("SMF_FMRI");
	load_smf_config();

	while ((c = getopt(argc, argv, "cdf:")) != -1) {
		switch (c) {
		case 'd':
			debug_mode = B_TRUE;
			break;
		case 'c':
			check_cfg = B_TRUE;
			break;
		case 'f':
			ustrfree(configfile);
			configfile = ustrdup(optarg, UMEM_NOFAIL);
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
	    lockingfd_log, &fdlock)) < 0) {
		errx(EXIT_FAILURE, "bunyan_stream_add() failed: %s",
		    strerror(rc));
	}
	main_log = log;

	if ((config = config_read(configfile)) == NULL)
		exit(EXIT_FAILURE);

	if (check_cfg)
		exit(EXIT_SUCCESS);

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

	worker_init(wk_initial_nworkers);
	pfkey_init();
	ikev2_cookie_init();
	ikev2_door_init(DOORNM);
	inbound_init();

	main_loop(fd);

	worker_fini();
	ikev2_sa_fini();
	pkt_fini();
	pkcs11_fini();

	(void) bunyan_stream_remove(log, "stdout");
	return (EXIT_SUCCESS);
}

/* Temp function to fire off IKE_SA_INIT exchanges */
static void
do_immediate(void)
{
	for (size_t i = 0; config->cfg_rules[i] != NULL; i++) {
		config_rule_t *rule = config->cfg_rules[i];

		if (!rule->rule_immediate)
			continue;

		RULE_REFHOLD(rule);
		VERIFY(worker_send_cmd(WC_START, rule));
	}
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
	config_t *new_config = NULL;
	config_t *old_config = NULL;

	VERIFY(!IS_WORKER);

	(void) bunyan_info(log, "reloading configuration", BUNYAN_T_END);

	if ((new_config = config_read(configfile)) == NULL)
		return;

	worker_suspend();

	VERIFY0(rw_wrlock(&config_rule_lock));
	old_config = config;
	config = new_config;
	VERIFY0(rw_unlock(&config_rule_lock));

	preshared_reload();

	worker_resume();

	config_free(old_config);
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

	(void) bunyan_trace(log, "Signal thread awaiting signals",
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
		(void) sig2str(signo, sigbuf + 3);

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

	if ((rc = thr_create(NULL, 0, signal_thread, child, THR_DETACHED,
	    &signal_tid)) != 0) {
		TSTDERR(rc, fatal,
		    "Signal handling thread creation failed");
		exit(EXIT_FAILURE);
	}
}

/* BEGIN CSTYLED */
#define	SCFERR(level, msg, ...)						\
	(void) bunyan_##level(log, msg,					\
	    BUNYAN_T_INT32, "scf_error", (int32_t)scf_error(),		\
	    BUNYAN_T_STRING, "scf_errormsg", scf_strerror(scf_error()),	\
	    ## __VA_ARGS__, BUNYAN_T_END)
/* END CSTYLED */

static void
load_smf_config(void)
{
	scf_handle_t *handle = NULL;
	scf_scope_t *sc = NULL;
	scf_service_t *svc = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *value_iter = NULL;
	char *str = NULL;
	uint64_t val = 0;

	if (my_fmri == NULL)
		return;

	handle = scf_handle_create(SCF_VERSION);
	sc = scf_scope_create(handle);
	svc = scf_service_create(handle);
	pg = scf_pg_create(handle);
	prop = scf_property_create(handle);
	value = scf_value_create(handle);
	value_iter = scf_iter_create(handle);

	if (handle == NULL || sc == NULL || svc == NULL || pg == NULL ||
	    prop == NULL || value == NULL || value_iter == NULL) {
		SCFERR(error, "unable to contact svc.configd");
		goto done;
	}

	if (scf_handle_bind(handle) != 0) {
		SCFERR(error, "unable to bind smf(5) handle");
		goto done;
	}

	if (scf_handle_decode_fmri(handle, my_fmri, sc, svc, NULL, NULL, NULL,
	    0) != 0) {
		SCFERR(error, "Unable to decode fmri",
		    BUNYAN_T_STRING, "fmri", my_fmri);
		goto done;
	}

	for (size_t i = 0; i < ARRAY_SIZE(scf_cfg); i++) {
		struct scf_cfg *c = &scf_cfg[i];
		size_t len = 0;

		/* XXX: Do we want to let these value be optional? */
		if (scf_pg_get_property(pg, c->sc_name, prop) != 0) {
			SCFERR(error, "Error getting property",
			    BUNYAN_T_STRING, "property", c->sc_name);
			goto done;
		}

		if (scf_property_is_type(prop, c->sc_type) != 0) {
			/* XXX: Add types */
			SCFERR(error, "SMF property is the incorrect type",
			    BUNYAN_T_STRING, "property", c->sc_name);
			goto done;
		}

		if (scf_property_get_value(prop, value) != 0) {
			SCFERR(error, "Error reading SMF property value",
			    BUNYAN_T_STRING, "property", c->sc_name);
			goto done;
		}

		switch (c->sc_type) {
		case SCF_TYPE_COUNT:
			if (scf_value_get_count(value, &val) != 0) {
				SCFERR(error,
				    "Error reading SMF property as a number",
				    BUNYAN_T_STRING, "property", c->sc_name);
				continue;
			}
			*(uint64_t *)c->sc_val = (uint64_t)val;
			break;
		case SCF_TYPE_ASTRING:
			len = scf_value_get_astring(value, NULL, 0);
			str = umem_alloc(len + 1, UMEM_DEFAULT);
			if (str == NULL) {
				(void) bunyan_error(log,
				    "No memory to read SMF configuration",
				    BUNYAN_T_END);
				goto done;
			}
			if (scf_value_get_astring(value, str, len + 1) != 0) {
				SCFERR(error,
				    "Error reading SMF property as string",
				    BUNYAN_T_STRING, "property", c->sc_name);
				umem_free(str, len + 1);
				str = NULL;
				goto done;
			}
			*(char **)c->sc_val = str;
			break;
		default:
			INVALID(c->sc_type);
		}
	}

done:
	scf_iter_destroy(value_iter);
	scf_value_destroy(value);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_service_destroy(svc);
	scf_scope_destroy(sc);
	scf_handle_destroy(handle);
}
