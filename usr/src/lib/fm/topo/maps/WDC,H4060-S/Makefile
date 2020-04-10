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
# Copyright (c) 2018, Joyent, Inc.
#

# NOTE: The name of the xml file we are building is 'platform'
# specific, but its build is structured as 'arch' specific since
# 'uname -i' on all x86 platforms returns i86pc.

ARCH = i86pc
CLASS = arch
DTDFILE = topology.dtd.1

TOPOFILE = \
	H4060-S-hc-topology.xml \
	H4060-S-chassis-hc-topology.xml \
	H4060-S-disk-hc-topology.xml \

SRCDIR = ../WDC,H4060-S

PLATFORM = H4060-S

CLOBBERFILES +=	H4060-S-disk-hc-topology.xml

include ../Makefile.map
