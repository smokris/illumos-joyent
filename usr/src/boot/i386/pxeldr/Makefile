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
# Copyright 2015 Toomas Soome <tsoome@me.com>
#

include $(SRC)/Makefile.master
include $(SRC)/boot/Makefile.inc

ROOT_BOOT = $(ROOT)/boot

DD=		/usr/bin/dd

CPPFLAGS += -I../../sys
CPPFLAGS += -I../common

CCASFLAGS= -Wa,--divide

include ../Makefile.inc

BTXDIR= ../btx

PROG=	$(LDR)
INTERNALPROG=
FILES=	$(BOOT)
MAN=	$(BOOT).8
SRCS=	$(LDR).S
OBJS=	$(LDR).o
CLEANFILES= $(BOOT) $(OBJS)

BOOT=	pxeboot
LDR=	pxeldr
ORG=	0x7c00
LOADER=	loader
FILEMODE=0444

#CFLAGS +=	-DPROBE_KEYBOARD

#.if defined(BOOT_PXELDR_ALWAYS_SERIAL)
#CFLAGS+=-DALWAYS_SERIAL
#.endif

LOADERBIN= ../loader/loader.bin

CLEANFILES += $(BOOT).tmp

$(BOOT): $(LDR) $(LOADER)
	$(CAT) $(LDR) $(LOADER) > $@.tmp
	$(DD) if=$@.tmp of=$@ obs=2k conv=sync
	$(RM) $@.tmp

LDFLAGS += $(GLDTARGET) -e start -Ttext $(ORG) -N -S --oformat binary

CLEANFILES += $(LOADER) $(LDR)

$(LDR): $(OBJS)
	$(GLD) $(LDFLAGS) -o $@ $^

$(LOADER): $(LOADERBIN) $(BTXLDR) $(BTXKERN)
	$(BTXLD) -f aout -e $(LOADER_ADDRESS) -o $@ -l $(BTXLDR) \
	    -b $(BTXKERN) $(LOADERBIN)

all: $(BOOT)

install: $(BOOT:%=$(ROOT_BOOT)/%)

clobber: clean
clean:
	$(RM) $(CLEANFILES)

$(ROOT_BOOT)/%: %
	$(INS.file)
