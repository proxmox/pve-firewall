
export PREFIX=/usr
export BINDIR=${PREFIX}/bin
export SBINDIR=${PREFIX}/sbin
export MANDIR=${PREFIX}/share/man
export DOCDIR=${PREFIX}/share/doc/pve-firewall
export MAN1DIR=${MANDIR}/man1/
export MAN8DIR=${MANDIR}/man8/
export PERLDIR=${PREFIX}/share/perl5
export BASHCOMPLDIR=${PREFIX}/share/bash-completion/completions

export NOVIEW=1
include /usr/share/pve-doc-generator/pve-doc-generator.mk

all: pve-firewall.8 pvefw-logger

pve-firewall.bash-completion: PVE/Service/pve_firewall.pm
	perl -I. -T -e "use PVE::Service::pve_firewall; PVE::Service::pve_firewall->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

CPPFLAGS:=$(shell dpkg-buildflags --get CPPFLAGS)
CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

pvefw-logger: pvefw-logger.c
	gcc -Wall -Werror pvefw-logger.c -o pvefw-logger -std=gnu99 \
	$(CPPFLAGS) $(CFLAGS) $(LDFLAGS) \
	$(shell pkg-config libnetfilter_log glib-2.0 --libs --cflags)

.PHONY: install
install: pve-firewall pve-firewall.8 pve-firewall.bash-completion pvefw-logger
	make -C PVE install
	install -d -m 0755 ${DESTDIR}/${SBINDIR}
	install -m 0755 pve-firewall ${DESTDIR}/${SBINDIR}
	install -m 0755 --strip pvefw-logger ${DESTDIR}/${SBINDIR}
	install -d ${DESTDIR}/${MAN8DIR}
	install -m 0644 pve-firewall.8 ${DESTDIR}/${MAN8DIR}
	install -m 0644 -D pve-firewall.bash-completion ${DESTDIR}/${BASHCOMPLDIR}/pve-firewall
	install -d -m 0755 ${DESTDIR}/usr/lib/sysctl.d/
	install -m 0644 pve-firewall-sysctl.conf ${DESTDIR}/usr/lib/sysctl.d/pve-firewall.conf

.PHONY: clean
clean: 	
	make -C PVE clean
	make cleanup-docgen
	rm -rf pvefw-logger 
	find . -name '*~' -exec rm {} ';'


.PHONY: distclean
distclean: clean

