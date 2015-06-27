
export PREFIX=/usr
export BINDIR=${PREFIX}/bin
export SBINDIR=${PREFIX}/sbin
export MANDIR=${PREFIX}/share/man
export DOCDIR=${PREFIX}/share/doc/pve-firewall
export PODDIR=${DOCDIR}/pod
export MAN1DIR=${MANDIR}/man1/
export PERLDIR=${PREFIX}/share/perl5

all: pve-firewall.1 pvefw-logger

%.1: %.1.pod
	rm -f $@
	cat $<|pod2man -n $* -s 1 -r ${VERSION} -c "Proxmox Documentation" >$@

pve-firewall.1.pod: pve-firewall
	perl -I.. ./pve-firewall printmanpod >$@

CPPFLAGS:=$(shell dpkg-buildflags --get CPPFLAGS)
CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

pvefw-logger: pvefw-logger.c
	gcc -Wall -Werror pvefw-logger.c -o pvefw-logger -std=gnu99 \
	$(CPPFLAGS) $(CFLAGS) $(LDFLAGS) \
	$(shell pkg-config libnetfilter_log glib-2.0 gthread-2.0 --libs --cflags)

.PHONY: install
install: pve-firewall pve-firewall.1 pve-firewall.1.pod pvefw-logger
	make -C PVE install
	install -d -m 0755 ${DESTDIR}/${SBINDIR}
	install -m 0755 pve-firewall ${DESTDIR}/${SBINDIR}
	install -m 0755 --strip pvefw-logger ${DESTDIR}/${SBINDIR}
	install -d ${DESTDIR}/${MAN1DIR}
	install -m 0644 pve-firewall.1 ${DESTDIR}/${MAN1DIR}
	install -d ${DESTDIR}/${PODDIR}
	install -m 0644 pve-firewall.1.pod ${DESTDIR}/${PODDIR}


.PHONY: clean
clean: 	
	make -C PVE clean
	rm -rf *~ pvefw-logger

.PHONY: distclean
distclean: clean

