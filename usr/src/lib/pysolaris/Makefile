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
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

include	../Makefile.lib

SUBDIRS=
$(BUILDPY2)SUBDIRS += $(MACH)
$(BUILD64)$(BUILDPY2)SUBDIRS += $(MACH64)
$(BUILD64)$(BUILDPY3)SUBDIRS += py3
$(BUILD64)$(BUILDPY3b)SUBDIRS += py3b

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber

PYCFIND =	$(FIND) . -name '*.pyc'
PYCFILES =	$(PYCFIND:sh)

.KEEP_STATE:

all install clean: $(SUBDIRS)
clobber: $(SUBDIRS)
	$(RM) $(PYCFILES)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../../Makefile.msg.targ
