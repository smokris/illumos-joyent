#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2018, Joyent, Inc.
#

PROG= in.ikev2d
MANIFEST=ikev2.xml

OBJS = \
	config.o		\
	config_parse.o		\
	dh.o			\
	door.o			\
	fromto.o		\
	ikev2_child_sa.o	\
	ikev2_common.o		\
	ikev2_cookie.o		\
	ikev2_enum.o		\
	ikev2_ike_auth.o	\
	ikev2_pkt.o		\
	ikev2_pkt_check.o	\
	ikev2_proto.o		\
	ikev2_sa.o		\
	ikev2_sa_init.o		\
	inbound.o		\
	main.o			\
	pfkey.o			\
	preshared.o		\
	prf.o			\
	pkcs11.o		\
	pkt.o			\
	ts.o			\
	util.o			\
	worker.o


include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.cmd.64
include $(SRC)/cmd/Makefile.ctf

# Lint doesn't like ## __VA_ARGS__ macros
LINTFLAGS += $(C99LMODE) -D_XOPEN_SOURCE=600 -erroff=E_ARGUMENT_MISMATCH

CSTD = $(CSTD_GNU99)
CFLAGS += $(CCVERBOSE)
CPPFLAGS += -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -D__EXTENSIONS__

# Use X/Open sockets for fromto.c so we can use control messages for
# source address selection
fromto.o :=	CPPFLAGS += -D_XOPEN_SOURCE=600

# ... but as a consequence, you have to disable a few lint checks.
LINTFLAGS += -erroff=E_INSONS_ARG_DECL2 -errorr=E_INCONS_VAL_TYPE_DECL2

LDLIBS += -lbunyan \
	-lcmdutils \
	-lcryptoutil \
	-linetutil \
	-lipsecutil \
	-lnsl \
	-lnvpair \
	-lpkcs11 \
	-lperiodic \
	-lrefhash \
	-lscf \
	-lumem \
	-lxnet

FILEMODE = 0555
GROUP = bin

CLEANFILES += $(OBJS)

ROOTMANIFESTDIR = $(ROOTSVCNETWORKIPSEC)
ROOTMANIFEST = $(ROOTMANIFESTDIR)/$(MANIFEST)

.KEEP_STATE:

all:	$(PROG)

clean:
	-$(RM) $(CLEANFILES)

# XXX: Disable lint for the moment
lint: #lint_SRCS

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

include ../Makefile.lib

install: $(PROG) $(ROOTMANIFEST)
	-$(RM) $(ROOTLIBINETPROG)
	-$(LN) $(ISAEXEC) $(ROOTLIBINETPROG)

check:	$(CHKMANIFEST)

include $(SRC)/cmd/Makefile.targ
