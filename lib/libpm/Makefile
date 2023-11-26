
PLATFORM ?= $(shell sh -c 'uname -s | tr "[A-Z]" "[a-z]"')
SONAME ?= libpm.so.1.0
SONAME_GENERIC ?= libpm.so

TOPDIR?=$(CURDIR)/../..
include $(TOPDIR)/cflags.mk

CC?=gcc
AR?=ar

CFLAGS += -Wall -Wextra -Werror -I${UINET_DESTDIR}/include
CFLAGS_DEBUG = $(CFLAGS) -O0 -g $(CFLAGS_DEBUG_EXTRA) $(DEBUG_FLAGS)
CFLAGS_FAST = $(CFLAGS) -O3 $(CFLAGS_FAST_EXTRA) $(DEBUG_FLAGS)
CFLAGS_LIB = $(CFLAGS) $(DEBUG_FLAGS) -fPIC

LDFLAGS_LIB = $(LDFLAGS) -shared -L${UINET_DESTDIR}/lib -luinet -lssl -lcrypto

ifneq (darwin,$(PLATFORM))
# TODO(bnoordhuis) The native SunOS linker expects -h rather than -soname...
LDFLAGS_LIB += -Wl,-soname=$(SONAME)
endif

pm_sock.o: pm_sock.c pm_sock.h Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS_LIB) -c pm_sock.c -o pm_sock.o

library: pm_sock.o
	$(CC) $(LDFLAGS_LIB) -o $(SONAME) $<
	ln -sf $(SONAME) $(SONAME_GENERIC)

package: pm_sock.o
	$(AR) rcs pm_sock.a pm_sock.o

default: all

all: library package

clean:
	rm -f *.o *.a *.so

install:
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/lib
	${UINET_INSTALL_DIR} -d ${UINET_DESTDIR}/include
	${UINET_INSTALL_LIB} libpm.a ${UINET_DESTDIR}/lib
	${UINET_INSTALL_LIB} libpm.so ${UINET_DESTDIR}/lib
	${UINET_INSTALL_INC} pm_sock.h ${UINET_DESTDIR}/include

