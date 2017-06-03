
#include "thread.h"

typedef void (*initfn_t)(void);

typedef struct thr_init_s {
	ike_thread_t	ttype;
	initfn_t	*init_fns;
} thr_init_t;

extern void ikev2_timer_init;
extern void ikev2_timer_thread_init;

static initfn_t init_fns[] = {
	ikev2_timer_init,
	NULL
};

static initfn_t worker_init_fns[] = {
	ikev2_timer_thread_init,
	NULL
};

static thr_init_t thr_init_fns[] = {
	{ TT_WORKER, worker_init_fns }
	{ 0, NULL }
};


