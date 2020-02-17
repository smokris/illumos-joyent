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
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/timer.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/cyclic.h>

/*
 * This clock backend is to implement CPU-usage-driven timers, both
 * per-thread, and per-process.  Some programs wish to only fire timers once
 * they've used a sufficient amount of CPU time, and this clock backend gives
 * that to programs.
 *
 * XXX KEBE SAYS CHECKPOINT STATE HERE.
 *
 * The idea is that we fire a cyclic <= "when" later.  THEN we compare in our
 * fire-function the CPU time (either per-thread or per-proc) elapsed vs. our
 * "when".  If doing per-thread CPU, we can fire this cyclic "when" later, as
 * elapsed CPU time for a thread will never dominate elapsed time.  A
 * subsequent cyclic can be fired if enough CPU time has not elapsed yet,
 * subject to the clamping logic for unprivileged processes per
 * clock_highres.c.
 *
 * A process with many threads, however, can have CPU time elapsed be more
 * than the "when" equivalent provided, so the cyclic should be (again,
 * subject to the aforementioned clamping logic) perhaps set to something
 * smaller than "when", perhaps "when" / number-of-threads?
 */

static clock_backend_t clock_thread_cpu;
static clock_backend_t clock_proc_cpu;

/* See clock_highres.c --> using their 200us limit for the non-privileged. */
extern long clock_highres_interval_min;

/*
 * clock_common_*() functions are shared betwen both per-thread and per-proc.
 */

/*
 * We can't set the time for either per-thread or per-cpu.
 * IF it turns out Linux needs you to (and we need it for LX zones), revisit.
 */
static int
clock_common_cpu_settime(timespec_t *ts __unused)
{
	return (set_errno(EINVAL));
}

/*
 * We're using cyclics.
 */
static int
clock_common_cpu_getres(timespec_t *ts)
{
	hrt2ts(cyclic_getres(), (timestruc_t *)ts);

	return (0);
}

/*
 * clock_thread_*() functions are for the per-thread backend.
 */

typedef struct cpu_thread_timer_s {
	klwp_t *ctt_lwp;
	hrtime_t ctt_cpu_elapsed;
	cyclic_id_t ctt_cyclic;
} cpu_thread_timer_t;

static hrtime_t
clock_thread_cpu_gettime_lwp(timespec_t *ts, klwp_t *lwp)
{
	struct mstate *ms = &lwp->lwp_mstate;
	hrtime_t snsecs, unsecs;

	/* Based on getrusage_lwp() in "rusagesys.c": */
	unsecs = ms->ms_acct[LMS_USER];
	snsecs = ms->ms_acct[LMS_SYSTEM] + ms->ms_acct[LMS_TRAP];

	scalehrtime(&unsecs);
	scalehrtime(&snsecs);

	hrt2ts(unsecs + snsecs, ts);

	return (0);
}

static int
clock_thread_cpu_gettime(timespec_t *ts)
{
	return (clock_thread_cpu_gettime_lwp(ts, ttolwp(curthread)));
}

static int
clock_thread_cpu_timer_gettime(itimer_t *it, struct itimerspec *when)
{
	/* XXX KEBE SAYS FILL ME IN! */

	return (0);
}

static int
clock_thread_cpu_timer_settime(itimer_t *it, int flags,
    const struct itimerspec *when)
{
	cpu_thread_timer_t *ctt = (cpu_thread_timer_t *)it->it_arg;

	/* XXX KEBE SAYS FILL ME IN! */
	return (0);
}

static int
clock_thread_cpu_timer_delete(itimer_t *it)
{
	/* XXX KEBE SAYS FILL ME IN! */
	return (0);
}

static void
clock_thread_cpu_timer_lwpbind(itimer_t *it)
{
	/* XXX KEBE SAYS FILL ME IN! */
}

static int
clock_thread_cpu_timer_create(itimer_t *it, void (*fire)(itimer_t *))
{
	/* Use KM_SLEEP to guarantee allocation. */
	it->it_arg = kmem_zalloc(sizeof (cpu_thread_timer_t), KM_SLEEP);
	it->it_fire = fire;

	return (0);
}

/*
 * clock_proc_*() functions are for the per-process backend.
 */

#ifdef notyet

static int
clock_proc_cpu_gettime(timespec_t *ts)
{
	proc_t *p = ttoproc(curthread);
	hrtime_t snsecs, unsecs;

	/* Based on getrusage() in "rusagesys.c": */
	mutex_enter(&p->p_lock);
	unsecs = mstate_aggr_state(p, LMS_USER);
	snsecs = mstate_aggr_state(p, LMS_SYSTEM);
	mutex_exit(&p->p_lock);

	hrt2ts(unsecs + snsecs, &t);

	return (0);
}

#endif

void
clock_cpu_init(void)
{
	clock_backend_t *thread = &clock_thread_cpu;
	clock_backend_t *proc = &clock_proc_cpu;
	struct sigevent *threadev = &thread->clk_default;
	struct sigevent *procev = &proc->clk_default;

	threadev->sigev_signo = SIGALRM;
	threadev->sigev_notify = SIGEV_SIGNAL;
	threadev->sigev_value.sival_ptr = NULL;

#ifdef notyet
	/* Hey, they're identical w.r.t. this, right? */
	*procev = *threadev;
#endif

	thread->clk_clock_settime = clock_common_cpu_settime;
	thread->clk_clock_gettime = clock_thread_cpu_gettime;
	thread->clk_clock_getres = clock_common_cpu_getres;
	thread->clk_timer_gettime = clock_thread_cpu_timer_gettime;
	thread->clk_timer_settime = clock_thread_cpu_timer_settime;
	thread->clk_timer_delete = clock_thread_cpu_timer_delete;
	thread->clk_timer_lwpbind = clock_thread_cpu_timer_lwpbind;
	thread->clk_timer_create = clock_thread_cpu_timer_create;
	clock_add_backend(CLOCK_THREAD_CPUTIME_ID, &clock_thread_cpu);

#ifdef notyet
	proc->clk_clock_settime = clock_common_cpu_settime;
	proc->clk_clock_gettime = clock_proc_cpu_gettime;
	proc->clk_clock_getres = clock_common_cpu_getres;
	proc->clk_timer_gettime = clock_proc_cpu_timer_gettime;
	proc->clk_timer_settime = clock_proc_cpu_timer_settime;
	proc->clk_timer_delete = clock_proc_cpu_timer_delete;
	proc->clk_timer_lwpbind = clock_proc_cpu_timer_lwpbind;
	proc->clk_timer_create = clock_proc_cpu_timer_create;
	clock_add_backend(CLOCK_PROC_CPUTIME_ID, &clock_proc_cpu);
#endif
}
