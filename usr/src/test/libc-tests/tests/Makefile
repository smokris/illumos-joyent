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

#
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2015 Garrett D'Amore <garrett@damore.org>
# Copyright 2019 Joyent, Inc.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
#

SUBDIRS = \
	catopen \
	fpround \
	i18n \
	newlocale \
	nl_langinfo \
	priv_gettext \
	qsort \
	random \
	regex \
	select \
	stdio \
	strerror \
	symbols \
	threads \
	wcsrtombs \
	wctype

PROGS = \
	env-OS-4089 \
	aligned_alloc \
	c11_threads \
	c11_tss \
	call_once \
	endian \
	env-7076 \
	fnmatch \
	memchr \
	memset_s \
	posix_memalign \
	printf-9511 \
	psignal-5097 \
	quick_exit_order \
	quick_exit_status \
	set_constraint_handler_s \
	strcoll-strxfrm-6907 \
	timespec_get \
	wcsncasecmp \
	wcsncasecmp-7344 \
	wcsncasecmp-7350 \
	uchar \
	utimes

SCRIPTS = \
	quick_exit \
	psignal

CPPFLAGS += -D_REENTRANT

PROGS32 = $(PROGS:%=%.32)
PROGS64 = \
	$(PROGS:%=%.64) \
	printf-6961.64

aligned_alloc.32 :=	LDLIBS += -lproc
aligned_alloc.64 :=	LDLIBS64 += -lproc
posix_memalign.32 :=	LDLIBS += -lproc
posix_memalign.64 :=	LDLIBS64 += -lproc

memset_s.32 :=	CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1
memset_s.64 :=	CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1
set_constraint_handler_s.32 := CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1
set_constraint_handler_s.64 := CPPFLAGS += -D__STDC_WANT_LIB_EXT1__=1

ROOTOPTDIR = $(ROOT)/opt/libc-tests/tests
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTDIR)/%) \
	$(PROGS64:%=$(ROOTOPTDIR)/%) \
	$(SCRIPTS:%=$(ROOTOPTDIR)/%)

include $(SRC)/cmd/Makefile.cmd

all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber
lint    :=      TARGET = lint

.KEEP_STATE:

install: $(SUBDIRS) $(ROOTOPTPROGS)

all: $(SUBDIRS) $(PROGS32) $(PROGS64)

clean lint: $(SUBDIRS)

$(ROOTOPTPROGS): $(PROGS32) $(PROGS64) $(ROOTOPTDIR)

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTOPTDIR)/%: %
	$(INS.file)

$(ROOTOPTDIR)/%: %.ksh
	$(INS.rename)

%.64: %.c
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.c
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)

clobber: $(SUBDIRS)
	$(RM) $(PROGS32) $(PROGS64)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
