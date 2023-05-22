DESTDIR=
PREFIX= /usr
BINDIR=${DESTDIR}/${PREFIX}/bin
SBINDIR=${DESTDIR}/${PREFIX}/sbin
MANDIR=${DESTDIR}/${PREFIX}/share/man
DOCDIR=${DESTDIR}/${PREFIX}/share/doc/pve-firewall
MAN1DIR=${MANDIR}/man1/
MAN8DIR=${MANDIR}/man8/
BASHCOMPLDIR=${DESTDIR}/${PREFIX}/share/bash-completion/completions
ZSHCOMPLDIR=${DESTDIR}/${PREFIX}/share/zsh/vendor-completions

-include /usr/share/pve-doc-generator/pve-doc-generator.mk

all: pve-firewall.8 pvefw-logger

pve-firewall.bash-completion: PVE/Service/pve_firewall.pm
	perl -I. -T -e "use PVE::Service::pve_firewall; PVE::Service::pve_firewall->generate_bash_completions();" >$@.tmp
	mv $@.tmp $@

pve-firewall.zsh-completion: PVE/Service/pve_firewall.pm
	perl -I. -T -e "use PVE::Service::pve_firewall; PVE::Service::pve_firewall->generate_zsh_completions();" >$@.tmp
	mv $@.tmp $@

CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
CFLAGS+=$(shell pkg-config libnetfilter_log libnetfilter_conntrack glib-2.0 --libs --cflags)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

pvefw-logger: pvefw-logger.c
	gcc -Wall -Werror pvefw-logger.c -o pvefw-logger -std=gnu99 $(CFLAGS) $(LDFLAGS)

.PHONY: install
install: pve-firewall pve-firewall.8 pve-firewall.bash-completion pve-firewall.zsh-completion pvefw-logger
	make -C PVE install
	install -d -m 0755 ${SBINDIR}
	install -m 0755 pve-firewall ${SBINDIR}
	install -m 0755 pvefw-logger ${SBINDIR}
	install -d ${MAN8DIR}
	install -m 0644 pve-firewall.8 ${MAN8DIR}
	install -m 0644 -D pve-firewall.bash-completion ${BASHCOMPLDIR}/pve-firewall
	install -m 0644 -D pve-firewall.zsh-completion ${ZSHCOMPLDIR}/_pve-firewall
	install -d -m 0755 ${DESTDIR}/usr/lib/sysctl.d/
	install -m 0644 pve-firewall-sysctl.conf ${DESTDIR}/usr/lib/sysctl.d/pve-firewall.conf

.PHONY: clean
clean: 	
	make -C PVE clean
	rm -f *.xml.tmp *.1 *.5 *.8 *(synopsis,opts).adoc docinfo.xml *~
	rm -rf pvefw-logger


.PHONY: distclean
distclean: clean
