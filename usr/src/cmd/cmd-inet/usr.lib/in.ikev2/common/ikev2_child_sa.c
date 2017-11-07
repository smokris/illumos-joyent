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
 * Copyright (c) 2017 Joyent, Inc.
 */

#include <strings.h>
#include <sys/debug.h>
#include "config.h"
#include "dh.h"
#include "ikev2.h"
#include "ikev2_common.h"
#include "ikev2_pkt.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pfkey.h"
#include "pkcs11.h"
#include "prf.h"
#include "worker.h"

struct child_sa_args {
	parsedmsg_t		*csa_pmsg;
	sadb_msg_t		*csa_srcmsg;
	uint8_t			csa_nonce_i[IKEV2_NONCE_MAX];
	size_t			csa_nonce_i_len;
	uint8_t			csa_nonce_r[IKEV2_NONCE_MAX];
	size_t			csa_nonce_r_len;
	uint32_t		csa_local_spi;
	uint32_t		csa_remote_spi;
	ikev2_dh_t		csa_dh;
	ikev2_sa_result_t	csa_results;
	boolean_t		csa_is_auth;
};

static void ikev2_create_child_sa_init_common(ikev2_sa_t *restrict,
    pkt_t *restrict req, struct child_sa_args *restrict);
static void ikev2_create_child_sa_init_resp(ikev2_sa_t *restrict,
    pkt_t *restrict, void *restrict);
static boolean_t create_keymat(ikev2_sa_t *restrict, uint8_t *restrict, size_t,
    uint8_t *restrict, size_t, prfp_t *restrict);
static uint8_t get_satype(parsedmsg_t *);

void
ikev2_create_child_sa_init_auth(ikev2_sa_t *restrict sa, pkt_t *restrict req,
    parsedmsg_t *pmsg)
{
	struct child_sa_args *csa = NULL;
	pkt_payload_t *ni = NULL;
	pkt_payload_t *nr = NULL;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));
	VERIFY3U(pkt_header(req)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);

	csa = umem_zalloc(sizeof (*csa), UMEM_DEFAULT);
	if (csa == NULL) {
		(void) bunyan_error(log,
		    "No memory to perform CREATE_CHILD_SA exchange",
		    BUNYAN_T_END);
		pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);
		parsedmsg_free(pmsg);
		return;
	}

	ni = pkt_get_payload(sa->init_i, IKEV2_PAYLOAD_NONCE, NULL);
	nr = pkt_get_payload(sa->init_r, IKEV2_PAYLOAD_NONCE, NULL);
	csa->csa_is_auth = B_TRUE;
	csa->csa_pmsg = pmsg;

	/* Use this msg for the seq value in SADB_{GETSPI,ADD,UPDATE} */
	if (PMSG_FROM_KERNEL(csa->csa_pmsg))
		csa->csa_srcmsg = pmsg->pmsg_samsg;

	(void) memcpy(csa->csa_nonce_i, ni->pp_ptr, ni->pp_len);
	csa->csa_nonce_i_len = ni->pp_len;
	(void) memcpy(csa->csa_nonce_r, nr->pp_ptr, nr->pp_len);
	csa->csa_nonce_r_len = nr->pp_len;

	ikev2_create_child_sa_init_common(sa, req, csa);
}

void
ikev2_create_child_sa_init(ikev2_sa_t *restrict sa, parsedmsg_t *restrict pmsg)
{
	struct child_sa_args *csa = NULL;
	pkt_t *req = NULL;

	VERIFY(IS_WORKER);
	VERIFY(!MUTEX_HELD(&sa->i2sa_queue_lock));
	VERIFY(MUTEX_HELD(&sa->i2sa_lock));

	csa = umem_zalloc(sizeof (*csa), UMEM_DEFAULT);
	if (csa == NULL) {
		(void) bunyan_error(log,
		    "No memory to perform CREATE_CHILD_SA exchange",
		    BUNYAN_T_END);
		goto fail;
	}

	csa->csa_pmsg = pmsg;
	if (pmsg->pmsg_samsg->sadb_msg_pid != getpid())
		csa->csa_srcmsg = pmsg->pmsg_samsg;
	csa->csa_dh = sa->i2sa_rule->rule_p2_dh;

	req = ikev2_pkt_new_exchange(sa, IKEV2_EXCH_CREATE_CHILD_SA);
	if (req == NULL)
		goto fail;

	/* This is the first payload, there should always be space for it */
	VERIFY(ikev2_add_sk(req));
	ikev2_create_child_sa_init_common(sa, req, csa);
	return;

fail:
	pfkey_send_error(pmsg->pmsg_samsg, ENOMEM);
	parsedmsg_free(pmsg);
	if (csa != NULL) {
		explicit_bzero(csa, sizeof (*csa));
		umem_free(csa, sizeof (*csa));
	}
}

/* We are the initiator */
static void
ikev2_create_child_sa_init_common(ikev2_sa_t *restrict sa, pkt_t *restrict req,
    struct child_sa_args *restrict csa)
{
	parsedmsg_t *pmsg = csa->csa_pmsg;
	sockaddr_u_t src = { .sau_ss = &sa->laddr };
	sockaddr_u_t dest = { .sau_ss = &sa->raddr };
	ikev2_dh_t dh = IKEV2_DH_NONE;
	ikev2_spi_proto_t proto = satype_to_ikev2(get_satype(pmsg));
	uint8_t satype;
	boolean_t transport_mode = B_FALSE;

	if (pmsg->pmsg_isau.sau_ss == NULL)
		transport_mode = B_TRUE;

	satype = get_satype(pmsg);
	if (!pfkey_getspi(csa->csa_srcmsg, src, dest, satype,
	    &csa->csa_local_spi)) {
		goto fail;
	}

	/* XXX: IPcomp (when we add support) */

	if (transport_mode && !ikev2_add_notify(req, proto, csa->csa_local_spi,
	    IKEV2_N_USE_TRANSPORT_MODE, NULL, 0))
		goto fail;

	if (!ikev2_add_notify(req, proto, csa->csa_local_spi,
	    IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, 0))
		goto fail;

	if (!ikev2_add_notify(req, proto, csa->csa_local_spi,
	    IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, NULL, 0))
		goto fail;

	if (!ikev2_sa_from_acquire(req, pmsg, csa->csa_local_spi, dh))
		goto fail;

	if (!csa->csa_is_auth) {
		pkt_payload_t *nonce = NULL;
		size_t noncelen = ikev2_prf_outlen(sa->prf) / 2;

		if (!ikev2_add_nonce(req, NULL, noncelen))
			goto fail;

		nonce = pkt_get_payload(req, IKEV2_PAYLOAD_NONCE, NULL);
		(void) memcpy(csa->csa_nonce_i, nonce->pp_ptr, nonce->pp_len);
		csa->csa_nonce_i_len = nonce->pp_len;
	}

	/* TSi / TSr */

	if (!ikev2_send_req(req, ikev2_create_child_sa_init_resp, csa))
		goto fail;

fail:
	(void) pfkey_delete(csa->csa_local_spi, src, dest, B_FALSE);
	explicit_bzero(csa, sizeof (*csa));
	umem_free(csa, sizeof (*csa));
	ikev2_pkt_free(req);
}

/*
 * We are the responder.
 */
void
ikev2_create_child_sa_resp(pkt_t *restrict req, pkt_t *restrict resp)
{
	ikev2_sa_t *sa = req->pkt_sa;
	parsedmsg_t *pmsg = NULL;
	pkt_payload_t *ts_i = NULL;
	pkt_payload_t *ts_r = NULL;
	struct child_sa_args csa = { 0 };
	sockaddr_u_t src = { 0 };
	sockaddr_u_t dest = { 0 };
	sockaddr_u_t isrc = { 0 };
	sockaddr_u_t idest = { 0 };
	boolean_t transport_mode = B_FALSE;

	if (resp != NULL) {
		pkt_payload_t *ni = NULL;
		pkt_payload_t *nr = NULL;

		VERIFY3U(pkt_header(resp)->exch_type, ==, IKEV2_EXCH_IKE_AUTH);

		ni = pkt_get_payload(sa->init_i, IKEV2_PAYLOAD_NONCE, NULL);
		nr = pkt_get_payload(sa->init_r, IKEV2_PAYLOAD_NONCE, NULL);

		(void) memcpy(csa.csa_nonce_i, ni->pp_ptr, ni->pp_len);
		csa.csa_nonce_i_len = ni->pp_len;
		(void) memcpy(csa.csa_nonce_r, nr->pp_ptr, nr->pp_len);
		csa.csa_nonce_r_len = nr->pp_len;
		csa.csa_is_auth = B_TRUE;
	} else {
		resp = ikev2_pkt_new_response(req);
		if (resp == NULL)
			goto fail;
		if (!ikev2_add_sk(resp))
			goto fail;

		csa.csa_dh = sa->i2sa_rule->rule_p2_dh;
	}

	ts_i = pkt_get_payload(req, IKEV2_PAYLOAD_TSi, NULL);
	ts_r = pkt_get_payload(req, IKEV2_PAYLOAD_TSr, NULL);

	/* We are the responder, so source is the initiator, dest is us */
	src.sau_ss = &sa->raddr;
	dest.sau_ss = &sa->laddr;

	if (pkt_get_notify(req, IKEV2_N_USE_TRANSPORT_MODE, NULL) != NULL) {
		transport_mode = B_TRUE;
	} else {
		/* XXX: Extract inner src/dest from TS payloads */
	}

	if (!pfkey_inverse_acquire(src, dest, isrc, idest, &pmsg))
		goto fail;

	if (!pfkey_getspi(NULL, src, dest, get_satype(pmsg),
	    &csa.csa_local_spi))
		goto fail;

	if (!ikev2_sa_match_acquire(pmsg, csa.csa_dh, req, &csa.csa_results)) {
		if (!ikev2_no_proposal_chosen(resp, csa.csa_results.sar_proto))
			goto fail;
		goto done;
	}
	csa.csa_remote_spi = csa.csa_results.sar_spi;

	if (!csa.csa_is_auth && ikev2_get_dhgrp(req) !=
	    csa.csa_results.sar_dh) {
		if (!ikev2_invalid_ke(resp, csa.csa_results.sar_proto, 0,
		    csa.csa_results.sar_dh))
			goto fail;
		goto done;
	}

	if (transport_mode && !ikev2_add_notify(resp, csa.csa_results.sar_proto,
	    csa.csa_local_spi, IKEV2_N_USE_TRANSPORT_MODE, NULL, 0))
		goto fail;

	/* We currently don't support TFC PADDING */
	if (!ikev2_add_notify(resp, csa.csa_results.sar_proto,
	    csa.csa_local_spi, IKEV2_N_ESP_TFC_PADDING_NOT_SUPPORTED, NULL, 0))
		goto fail;

	/* and we always include non-first fragments */
	if (!ikev2_add_notify(resp, csa.csa_results.sar_proto,
	    csa.csa_local_spi, IKEV2_N_NON_FIRST_FRAGMENTS_ALSO, NULL, 0))
		goto fail;

	if (!ikev2_sa_add_result(resp, &csa.csa_results, csa.csa_local_spi))
		goto fail;

	if (!csa.csa_is_auth) {
		pkt_payload_t *ni = NULL, *nr = NULL;
		size_t noncelen = ikev2_prf_outlen(sa->prf) / 2;

		if (!ikev2_add_nonce(resp, NULL, noncelen))
			goto fail;

		ni = pkt_get_payload(req, IKEV2_PAYLOAD_NONCE, NULL);
		nr = pkt_get_payload(resp, IKEV2_PAYLOAD_NONCE, NULL);

		(void) memcpy(csa.csa_nonce_i, ni->pp_ptr, ni->pp_len);
		csa.csa_nonce_i_len = ni->pp_len;
		(void) memcpy(csa.csa_nonce_r, nr->pp_ptr, nr->pp_len);
		csa.csa_nonce_r_len = nr->pp_len;
	}

	if (!csa.csa_is_auth && csa.csa_results.sar_dh != IKEV2_DH_NONE) {
		pkt_payload_t *ke_i = NULL;
		uint8_t *ke = NULL;
		size_t kelen = 0;

		ke_i = pkt_get_payload(req, IKEV2_PAYLOAD_KE, NULL);

		/*
		 * XXX: If we ever support window sizes > 1, and can have
		 * multiple CREATE_CHILD_SA exchanges in flight, we will
		 * probably need to change this to support multiple DH
		 * keys
		 */
		if (ke_i == NULL || ke_i->pp_len <= sizeof (ikev2_ke_t)) {
			(void) bunyan_info(log,
			    "CREATE_CHILD_SA initiator negotiated a DH group "
			    "but didn't provide a public key", BUNYAN_T_END);
			goto fail;
		}

		/* Skip over fixed portion of payload */
		ke = ke_i->pp_ptr + sizeof (ikev2_ke_t);
		kelen = ke_i->pp_len - sizeof (ikev2_ke_t);

		if (!dh_genpair(csa.csa_results.sar_dh, &sa->dh_pubkey,
		    &sa->dh_privkey))
			goto fail;
		if (!dh_derivekey(sa->dh_privkey, ke, kelen, &sa->dh_key))
			goto fail;
		if (!ikev2_add_ke(resp, csa.csa_results.sar_dh, sa->dh_pubkey))
			goto fail;
	}

	/* XXX: TSi & TSr payloads */

	/* XXX: Create IPsec SA */

done:
	if (!ikev2_send_resp(resp))
		goto fail;

	/* Don't reuse the same DH key for additional child SAs */
	pkcs11_destroy_obj("child dh_pubkey", &sa->dh_pubkey);
	pkcs11_destroy_obj("child dh_privkey", &sa->dh_privkey);
	pkcs11_destroy_obj("child gir", &sa->dh_key);
	ikev2_pkt_free(req);
	return;

fail:
	pkcs11_destroy_obj("child dh_pubkey", &sa->dh_pubkey);
	pkcs11_destroy_obj("child dh_privkey", &sa->dh_privkey);
	pkcs11_destroy_obj("child gir", &sa->dh_key);
	ikev2_pkt_free(req);
	ikev2_pkt_free(resp);
}

/* We are initiator, this is the response from the peer */
static void
ikev2_create_child_sa_init_resp(ikev2_sa_t *restrict i2sa,
    pkt_t *restrict resp, void *restrict arg)
{
	struct child_sa_args *csa = arg;
	parsedmsg_t *pmsg = csa->csa_pmsg;
	ikev2_sa_result_t result = { 0 };

	if (resp == NULL) {
		if (PMSG_FROM_KERNEL(pmsg))
			pfkey_send_error(pmsg->pmsg_samsg, ETIME);
		explicit_bzero(csa, sizeof (*csa));
		umem_free(csa, sizeof (*csa));
		return;
	}

	if (pkt_get_notify(resp, IKEV2_N_NO_PROPOSAL_CHOSEN, NULL) != NULL) {
		(void) bunyan_info(log,
		    "Remote peer responded with NO_PROPOSAL_CHOSEN",
		    BUNYAN_T_END);
		goto remote_fail;
	}
	if (pkt_get_notify(resp, IKEV2_N_TS_UNACCEPTABLE, NULL) != NULL) {
		(void) bunyan_info(log,
		    "Remote peer responded to TS_UNACCEPTABLE",
		    BUNYAN_T_END);
		goto remote_fail;
	}

	if (!ikev2_sa_match_acquire(pmsg, csa->csa_dh, resp,
	    &csa->csa_results)) {
		/* TODO: log */
		goto fail;
	}

	if (!csa->csa_is_auth) {
		pkt_payload_t *nr = NULL;

		nr = pkt_get_payload(resp, IKEV2_PAYLOAD_NONCE, NULL);
		if (nr == NULL) {
			/* TODO: log */
			goto fail;
		}

		(void) memcpy(csa->csa_nonce_r, nr->pp_ptr, nr->pp_len);
		csa->csa_nonce_r_len = nr->pp_len;
	}

	if (!csa->csa_is_auth && csa->csa_results.sar_dh != IKEV2_DH_NONE) {
		pkt_payload_t *ke = NULL;
		uint8_t *kep = NULL;
		size_t kelen = 0;

		ke = pkt_get_payload(resp, IKEV2_PAYLOAD_KE, NULL);
		if (ke == NULL || ke->pp_len <= sizeof (ikev2_ke_t)) {
			/* TODO: log */
			goto fail;
		}

		kep = ke->pp_ptr + sizeof (ikev2_ke_t);
		kelen = ke->pp_len - sizeof (ikev2_ke_t);

		if (!dh_derivekey(i2sa->dh_privkey, kep, kelen, &i2sa->dh_key))
			goto fail;
	}

	/* TODO: Create child SA */

	return;

fail:
	if (PMSG_FROM_KERNEL(pmsg))
		pfkey_send_error(pmsg->pmsg_samsg, EINVAL);

	/* TODO: Information exchange to delete child SAs */
	ikev2_pkt_free(resp);
	return;

remote_fail:
	if (PMSG_FROM_KERNEL(pmsg))
		pfkey_send_error(pmsg->pmsg_samsg, EINVAL);

	/*
	 * Since we don't need to kick off a new exchange to tear
	 * things down, we can do both steps now.
	 */
	ikev2_sa_condemn(resp->pkt_sa);
	ikev2_sa_condemn(resp->pkt_sa);
	ikev2_pkt_free(resp);
}

static boolean_t
ikev2_create_child_sas(ikev2_sa_t *restrict sa,
    struct child_sa_args *restrict csa, boolean_t initiator)
{
	ikev2_sa_result_t *results = &csa->csa_results;
	uint8_t *encrkey_i = NULL, *encrkey_r = NULL;
	uint8_t *authkey_i = NULL, *authkey_r = NULL;
	size_t encrlen = 0;
	size_t authlen = 0;
	prfp_t prfp = { 0 };
	boolean_t ret = B_FALSE;

	if (results->sar_encr != IKEV2_ENCR_NONE) {
		encrlen = results->sar_encr_keylen;
		if (encrlen == 0)
			encrlen = encr_data[results->sar_encr].ed_keydefault;
		encrlen = SADB_8TO1(encrlen);

		encrkey_i = umem_zalloc(encrlen, UMEM_DEFAULT);
		encrkey_r = umem_zalloc(encrlen, UMEM_DEFAULT);
		if (encrkey_i == NULL || encrkey_r == NULL) {
			/* TODO: log */
			goto done;
		}
	}

	if (results->sar_auth != IKEV2_XF_AUTH_NONE) {
		authlen = SADB_8TO1(auth_data[results->sar_auth].ad_keylen);
		authkey_i = umem_zalloc(authlen, UMEM_DEFAULT);
		authkey_r = umem_zalloc(authlen, UMEM_DEFAULT);
		if (authkey_i == NULL || authkey_r == NULL) {
			/* TODO: log */
			goto done;
		}
	}

	if (!create_keymat(sa, csa->csa_nonce_i, csa->csa_nonce_i_len,
	    csa->csa_nonce_r, csa->csa_nonce_r_len, &prfp))
		goto done;

	if (encrkey_i != NULL && !prfplus(&prfp, encrkey_i, encrlen))
		goto done;
	if (authkey_i != NULL && !prfplus(&prfp, authkey_i, authlen))
		goto done;
	if (encrkey_r != NULL && !prfplus(&prfp, encrkey_r, encrlen))
		goto done;
	if (authkey_r != NULL && !prfplus(&prfp, authkey_r, authlen))
		goto done;

	if (!pfkey_sadb_add_update(sa, csa->csa_local_spi, results,
	    csa->csa_pmsg,
	    initiator ? encrkey_i : encrkey_r, encrlen,
	    initiator ? authkey_i : authkey_r, authlen,
	    0, initiator, B_FALSE))
		goto done;

	if (!pfkey_sadb_add_update(sa, csa->csa_remote_spi, results,
	    csa->csa_pmsg,
	    initiator ? encrkey_r : encrkey_i, encrlen,
	    initiator ? authkey_r : authkey_i, authlen,
	    csa->csa_local_spi, initiator, B_TRUE))
		goto done;

	ret = B_TRUE;

done:
	if (encrkey_i != NULL) {
		explicit_bzero(encrkey_i, encrlen);
		umem_free(encrkey_i, encrlen);
	}
	if (encrkey_r != NULL) {
		explicit_bzero(encrkey_r, encrlen);
		umem_free(encrkey_r, encrlen);
	}
	if (authkey_i != NULL) {
		explicit_bzero(authkey_i, authlen);
		umem_free(authkey_i, authlen);
	}
	if (authkey_r != NULL) {
		explicit_bzero(authkey_r, authlen);
		umem_free(authkey_r, authlen);
	}
	prfplus_fini(&prfp);
	return (ret);
}

static boolean_t
create_keymat(ikev2_sa_t *restrict sa, uint8_t *restrict ni, size_t ni_len,
    uint8_t *restrict nr, size_t nr_len, prfp_t *restrict prfp)
{
	boolean_t ret = B_FALSE;

	if (sa->dh_key != CK_INVALID_HANDLE) {
		uint8_t *gir = NULL;
		size_t girlen = 0;
		CK_RV rv = CKR_OK;

		rv = pkcs11_ObjectToKey(p11h(), sa->dh_key, (void **)&gir,
		    &girlen, B_FALSE);
		if (rv != CKR_OK) {
			PKCS11ERR(error, "pkcs11_ObjectToKey",
			    rv, BUNYAN_T_STRING, "objname", "gir");
			return (B_FALSE);
		}

		ret = prfplus_init(prfp, sa->prf, sa->sk_d,
		    gir, girlen, ni, ni_len, nr, nr_len, NULL);

		explicit_bzero(gir, girlen);
		free(gir);
	} else {
		ret = prfplus_init(prfp, sa->prf, sa->sk_d,
		    ni, ni_len, nr, nr_len, NULL);
	}
	return (ret);
}

/*
 * XXX: Just return the first non-UNSPEC SATYPE found.
 * This is very temporary until more of the CREATE_CHILD_SA stuff is complete.
 */
static uint8_t
get_satype(parsedmsg_t *pmsg)
{
	sadb_msg_t *msg = pmsg->pmsg_samsg;
	sadb_prop_t *prop = (sadb_prop_t *)pmsg->pmsg_exts[SADB_X_EXT_EPROP];
	sadb_x_ecomb_t *ecomb = NULL;

	if (prop == NULL || msg->sadb_msg_satype != SADB_SATYPE_UNSPEC)
		return (msg->sadb_msg_satype);

	ecomb = (sadb_x_ecomb_t *)(prop + 1);
	for (size_t i = 0; i < prop->sadb_x_prop_numecombs; i++) {
		sadb_x_algdesc_t *alg = (sadb_x_algdesc_t *)(ecomb + 1);

		for (size_t j = 0; j < ecomb->sadb_x_ecomb_numalgs;
		   j++, alg++) {
			if (alg->sadb_x_algdesc_satype != SADB_SATYPE_UNSPEC)
				return (alg->sadb_x_algdesc_satype);
		}

		prop = (sadb_prop_t *)alg;
	}

	return (SADB_SATYPE_UNSPEC);
}
