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

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	/*
	 * XXX KEBE SAYS:
	 *
	 * 1. Daemonize.
	 * 2. Have daemon open /dev/vxlnat.
	 * 3. Send flush message.
	 * 4. Read config file and send messages-per-line.
	 * 5. Sleep until signalled.
	 *	SIGHUP --> jump to step 3.
	 *	SIGINT (whatever ":kill" is) --> exit gracefully.
	 */
	return (1);
}
