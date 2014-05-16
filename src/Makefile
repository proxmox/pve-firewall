
export PREFIX=/usr
export BINDIR=${PREFIX}/bin
export SBINDIR=${PREFIX}/sbin
export MANDIR=${PREFIX}/share/man
export DOCDIR=${PREFIX}/share/doc
export MAN1DIR=${MANDIR}/man1/
export PERLDIR=${PREFIX}/share/perl5

all: pvefw-logger

CPPFLAGS:=$(shell dpkg-buildflags --get CPPFLAGS)
CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

pvefw-logger: pvefw-logger.c
	gcc -Wall -Werror pvefw-logger.c -o pvefw-logger -std=gnu99 \
	$(CPPFLAGS) $(CFLAGS) $(LDFLAGS) \
	$(shell pkg-config libnetfilter_log glib-2.0 gthread-2.0 --libs --cflags)

.PHONY: install
install: pve-firewall pvefw-logger
	make -C PVE install
	install -d -m 0755 ${DESTDIR}/${SBINDIR}
	install -m 0755 pve-firewall ${DESTDIR}/${SBINDIR}
	install -m 0755 --strip pvefw-logger ${DESTDIR}/${SBINDIR}

.PHONY: clean
clean: 	
	make -C PVE clean
	rm -rf *~ pvefw-logger

.PHONY: distclean
distclean: clean

