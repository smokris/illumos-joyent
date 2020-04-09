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
# Copyright (c) 2019, Joyent, Inc.
#

# NOTE: The name of the xml file we are building is 'platform'
# specific, but its build is structured as 'arch' specific since
# 'uname -i' on all x86 platforms returns i86pc.

ARCH = i86pc
CLASS = arch
DTDFILE = topology.dtd.1
#JOYENT_PLATFORMS = \
#	Joyent-Compute-Platform-3101-hc-topology.xml \
#	Joyent-Compute-Platform-3102-hc-topology.xml

#JOYENT_USBMAPS = \
#	Joyent-Compute-Platform-3101-usb.usbtopo \
#	Joyent-Compute-Platform-3102-usb.usbtopo
#ROOTJOYENTMAPS = $(JOYENT_PLATFORMS:%=$(arch_ROOTTOPOROOT)/%)
#ROOTJOYENTUSB = $(JOYENT_USBMAPS:%=$(arch_ROOTTOPOROOT)/%)

TOPOFILE = \
	SSG-6049P-E1CR60L-JI006-hc-topology.xml \
	SSG-6049P-E1CR60L-JI006-chassis-hc-topology.xml \
	SSG-6049P-E1CR60L-JI006-disk-hc-topology.xml \
	SSG-6049P-E1CR60L-JI006-ses-hc-topology.xml \
	SSG-6049P-E1CR60L-JI006-slot-hc-topology.xml \
	SSG-6049P-E1CR60L-JI006-usb.usbtopo

SRCDIR = ../SMCI,SSG-6049P-E1CR60L-JI006

PLATFORM = SSG-6049P-E1CR60L-JI006

#CLOBBERFILES += $(ROOTJOYENTMAPS)
CLOBBERFILES += SSG-6049P-E1CR60L-JI006-ses-hc-topology.xml

include ../Makefile.map

#install: $(ROOTJOYENTMAPS) $(ROOTJOYENTUSB)

#
# Note, the Joyent Compute Platform 310x is based on the SuperMicro
# SSG-6049P-E1CR60L-JI006. Because of that, the topo map used here will work for
# all such systems.
#
#$(ROOTJOYENTMAPS): SSG-6049P-E1CR60L-JI006-hc-topology.xml
#	$(RM) $@
#	$(SYMLINK) ./$? $@

#$(ROOTJOYENTUSB): SSG-6049P-E1CR60L-JI006-usb.usbtopo
#	$(RM) $@
#	$(SYMLINK) ./$? $@
