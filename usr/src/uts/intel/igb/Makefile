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
# Copyright (c) 2018, Joyent, Inc.

#
#	Paths to the base of the uts directory trees
#
UTSBASE = ../..

#
#	Define the module and object file sets.
#
MODULE		= igb
OBJECTS		= $(IGB_OBJS:%=$(OBJS_DIR)/%)
OBJECTS		+= $(E1000API_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/igb

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
# For now, disable these warnings; maintainers should endeavor
# to investigate and remove these for maximum coverage.
# Please do not carry these forward to new Makefiles.
#
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_cc=-erroff=E_STATEMENT_NOT_REACHED

# needs work
SMOFF += all_func_returns,indenting

CFLAGS		+= -I$(UTSBASE)/common/io/e1000api
CFLAGS		+= -I$(UTSBASE)/common/io/igb

#
#	Define targets
#
ALL_TARGET	= $(BINARY) $(CONFMOD)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

#
# Driver depends on MAC
#
LDFLAGS		+= -N misc/mac
MAPFILES	+= ddi mac random kernel ksensor

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/Makefile.mapfile
include $(UTSBASE)/intel/Makefile.targ
