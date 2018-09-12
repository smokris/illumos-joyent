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

/*
 * Writes (new rules) and reads (rule dump) go here.  So do the
 * ins/outs of reading & writing.
 */

#include <sys/ddi.h>
#include <sys/dtrace.h>
#include <inet/vxlnat.h>

/*
 * These are all initialized to NULL or 0.
 *
 * If a VXNM_DUMP is requested, these get allocated/set.  vxlnat_read()
 * calls will consume them, and once delivered the last bytes read will
 * cause these to be freed and reset to NULL/0.  Cheesy, but this is a
 * one-at-a-time thing.  Protected by vxlnat_mutex.
 */
static vxn_msg_t *vxlnat_dumpbuf;
static int vxlnat_dumpcount;
static int vxlnat_dumpcurrent;

int
vxlnat_read_dump(struct uio *uiop)
{
	int rc = 0;
	int dumpprogress = 0;

	mutex_enter(&vxlnat_mutex);
	/* XXX KEBE THINKS -- if no dump buffer, just return w/o data. */
	while (rc == 0 && vxlnat_dumpbuf != NULL &&
	    uiop->uio_resid >= sizeof (vxn_msg_t)) {
		rc = uiomove(vxlnat_dumpbuf + vxlnat_dumpcurrent,
		    sizeof (vxn_msg_t), UIO_READ, uiop);
		if (rc != 0) {
			/*
			 * XXX KEBE ASKS, destroy or preserve dumpstate?
			 * Fill in answer here.
			 */
			break;
		}
		vxlnat_dumpcurrent++;
		dumpprogress++;
		if (vxlnat_dumpcurrent == vxlnat_dumpcount) {
			kmem_free(vxlnat_dumpbuf,
			    vxlnat_dumpcount * sizeof (vxn_msg_t));
			vxlnat_dumpbuf = NULL;
			vxlnat_dumpcount = vxlnat_dumpcurrent = 0;
		}
	}

	/*
	 * If there's room at the end, just ignore that space for now.  Handy
	 * DTrace probe below notes amount of extra bytes..
	 */
	DTRACE_PROBE1(vxlnat__read__extrabytes, ssize_t, uiop->uio_resid);
	/* Note progress of dump with DTrace probes. */
	DTRACE_PROBE3(vxlnat__read__dumpprogress, int, dumpprogress, int,
	    vxlnat_dumpcurrent, int, vxlnat_dumpcount);

	mutex_exit(&vxlnat_mutex);
	return (rc);
}

int
vxlnat_command(vxn_msg_t *vxnm)
{
	int rc;

	switch (vxnm->vxnm_type) {
	case VXNM_VXLAN_ADDR:
		rc = vxlnat_vxlan_addr(&vxnm->vxnm_private);
		break;
	case VXNM_RULE:
		/*
		 * XXX KEBE SAYS add a (vnetid+prefix => external) rule.
		 */
		/* rc = vxlnat_nat_rule(vxnm); */
		rc = EOPNOTSUPP;	/* XXX KEBE SAYS NUKE ME */
		break;
	case VXNM_FIXEDIP:
		/*
		 * XXX KEBE SAYS add a 1-1 (vnetid+IP <==> external) rule.
		 */
		/* rc = vxlnat_fixed_ip(vxnm); */
		rc = EOPNOTSUPP;	/* XXX KEBE SAYS NUKE ME */
		break;
	case VXNM_FLUSH:
		/*
		 * XXX KEBE SAYS nuke ALL the state.
		 */
		/* rc = vxlnat_flush(); */
		rc = EOPNOTSUPP;	/* XXX KEBE SAYS NUKE ME */
		break;
	case VXNM_DUMP:
		/*
		 * XXX KEBE SAYS setup vxlnat_dump* above.
		 * XXX KEBE SAYS If function fails for reasons that aren't
		 * "dump in progress", make sure it keeps vxlnat_dump* stuff
		 * clean
		 */
		/* rc = vxlnat_dump(); */
		rc = EOPNOTSUPP;	/* XXX KEBE SAYS NUKE ME */
		break;
	default:
		rc = EINVAL;
		break;
	}

	return (rc);
}
