#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2018 Joyent, Inc.

PROG=		vxlnatd
MANIFEST=	vxlnatd.xml

include ../../../Makefile.cmd
ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)
$(ROOTMANIFEST)		:= FILEMODE= 444

.KEEP_STATE:

all:	$(PROG)

include ../Makefile.lib

CPPFLAGS += -D_REENTRANT
# LDLIBS += -lsocket -lslp

install:	all $(ROOTLIBINETPROG) $(ROOTMANIFEST) $(ROOTMETHOD)

check:		$(CHKMANIFEST)

clean:

include ../../../Makefile.targ

lint:		lint_PROG
