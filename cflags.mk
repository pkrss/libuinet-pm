HOST_OS:=$(shell uname -s)

DEBUG_FLAGS	?= -O0 -gdwarf-2

ifeq (MY_CFLAGS,"")
	MY_CFLAGS = -O2
endif

CFLAGS += $(MY_CFLAGS)

# BUILD_ALL ?= 1 # uncomment if want to build libs / [libuinet_demo libev libhttp_parser]

UINET_DESTDIR ?= $(UINET_DESTDIR)

ifeq (UINET_DESTDIR,"")
	UINET_DESTDIR = /usr/local/
endif

# PCAP_INCLUDE ?= 1  # uncomment if installed pcap

UINET_INSTALL	?= install
UINET_INSTALL_DIR ?= $(UINET_INSTALL) -m 0755
UINET_INSTALL_LIB ?= $(UINET_INSTALL) -m 0644
UINET_INSTALL_INC ?= $(UINET_INSTALL) -m 0644
UINET_INSTALL_BIN ?= $(UINET_INSTALL) -m 0755
