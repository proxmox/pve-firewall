DESTDIR=
PREFIX=/usr
PERLDIR=$(DESTDIR)/$(PREFIX)/share/perl5

SOURCES=pve_firewall.pm

.PHONY: install
install: $(SOURCES)
	install -d -m 0755 $(PERLDIR)/PVE/Service
	for i in $(SOURCES); do install -D -m 0644 $$i $(PERLDIR)/PVE/Service/$$i; done

clean:
