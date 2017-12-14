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
# Copyright 2017 Jason King.
# Copyright (c) 2017, Joyent, Inc.
#

PROG = in.ikev2d

CMD_OBJS =	config.o		\
		config_parse.o		\
		dh.o			\
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

COM_OBJS = list.o
COMDIR = $(SRC)/common/list
SRCDIR = ../common

OBJS = $(CMD_OBJS) $(COM_OBJS)
SRCS =	$(CMD_OBJS:%.o=$(SRCDIR)/%.c) \
	$(COM_OBJS:%.o=$(COMDIR)/%.c)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CPPFLAGS += -D__EXTENSIONS__
CPPFLAGS += -D_POSIX_PTHREAD_SEMANTICS

LINTFLAGS += $(C99LMODE) -erroff=E_STATIC_UNUSED
LINTFLAGS64 += $(C99LMODE) -erroff=E_STATIC_UNUSED

LINTFLAGS += -errfmt=macro

# Use X/Open sockets for fromto.c so we can use control messages for
# source address selection
fromto.o := CPPFLAGS += -D_XOPEN_SOURCE=600

# ... but as a consequence, you have to disable a few lint checks.
LINTFLAGS += -erroff=E_INCONS_ARG_DECL2 -erroff=E_INCONS_VAL_TYPE_DECL2
LINTFLAGS64 += -erroff=E_INCONS_ARG_DECL2 -erroff=E_INCONS_VAL_TYPE_DECL2

C99MODE = $(C99_ENABLE)
CFLAGS += $(CCVERBOSE) -D_REENTRANT
CFLAGS64 += $(CCVERBOSE) -D_REENTRANT
LDLIBS += -lnsl -lsecdb -lumem -lxnet -lipsecutil -lpkcs11 -lcryptoutil
LDLIBS += -lnvpair -lbunyan -lperiodic -linetutil -lrefhash -lcmdutils

FILEMODE = 0555
GROUP = bin

CLEANFILES += $(OBJS)

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(CLEANFILES)

lint: lint_SRCS

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

%.o: $(COMDIR)/%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include $(SRC)/cmd/Makefile.targ
