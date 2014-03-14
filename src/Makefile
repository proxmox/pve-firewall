
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc
MAN1DIR=${MANDIR}/man1/
PERLDIR=${PREFIX}/share/perl5

LIB_SOURCES=			\
	Firewall.pm

all: pvefw-logger

CPPFLAGS:=$(shell dpkg-buildflags --get CPPFLAGS)
CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

pvefw-logger: pvefw-logger.c
	gcc -Wall -Werror pvefw-logger.c -o pvefw-logger -std=gnu11 \
	$(CPPFLAGS) $(CFLAGS) $(LDFLAGS) \
	$(shell pkg-config libnetfilter_log glib-2.0 gthread-2.0 --libs --cflags)

.PHONY: install
install: pvefw pvefw-logger
	install -d -m 0755 ${DESTDIR}/${SBINDIR}
	install -m 0755 pvefw ${DESTDIR}/${SBINDIR}
	install -m 0755 --strip pvefw-logger ${DESTDIR}/${SBINDIR}
	install -d -m 0755 ${DESTDIR}${PERLDIR}/PVE
	for i in ${LIB_SOURCES}; do install -D -m 0644 PVE/$$i ${DESTDIR}${PERLDIR}/PVE/$$i; done


.PHONY: clean
clean: 	
	rm -rf *~ pvefw-logger

.PHONY: distclean
distclean: clean

