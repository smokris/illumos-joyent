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
 * Copyright 2018, Joyent, Inc.
 */

#ifndef _DH_IMPL_H
#define	_DH_IMPL_H

#include <sys/types.h>
#include "ikev2.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The type of public key */
typedef enum pktype {
	PK_DH,		/* Diffie-Hellman */
	PK_ECC		/* Ecliptic curve */
} pktype_t;

struct pkdh {
	uint8_t	*pkdh_prime;
	uint8_t	*pkdh_generator;
	size_t	pkdh_primelen;
	size_t	pkdh_genlen;
};

struct pkecc {
	uint8_t	*pkecc_oid;
	uint8_t	pkecc_oidlen;
};

typedef struct pkgroup {
	ikev2_dh_t	pk_id;
	pktype_t	pk_type;
	union {
		struct pkdh pkdhu;
		struct pkecc pkeccu;
	} pku;
} pkgroup_t;
#define	pk_prime	pku.pkdhu.pkdh_prime
#define	pk_generator	pku.pkdhu.pkdh_generator
#define	pk_primelen	pku.pkdhu.pkdh_primelen
#define	pk_genlen	pku.pkdhu.pkdh_genlen
#define	pk_oid		pku.pkeccu.pkecc_oid
#define	pk_oidlen	pku.pkeccu.pkecc_oidlen

extern pkgroup_t pk_groups[];
extern const size_t pk_ngroups;

#ifdef __cplusplus
}
#endif

#endif /* _DH_IMPL_H */
