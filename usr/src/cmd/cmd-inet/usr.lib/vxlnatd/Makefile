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
OBJS=		vxlnatd.o
SRCS=		$(OBJS:%.o=%.c)

include ../../../Makefile.cmd
include ../../../Makefile.ctf
ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)
$(ROOTMANIFEST)		:= FILEMODE= 444

CPPFLAGS += -D_REENTRANT
LDLIBS += -lbunyan
# LDLIBS += -lsocket -lslp


.KEEP_STATE:

all:	$(PROG)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o:	%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../Makefile.lib

install:	all $(ROOTLIBINETPROG) $(ROOTMANIFEST) $(ROOTMETHOD)

check:		$(CHKMANIFEST)

clean:

include ../../../Makefile.targ

lint:		lint_PROG
