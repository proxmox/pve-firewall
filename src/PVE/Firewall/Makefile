DESTDIR=
PREFIX=/usr
PERLDIR=$(DESTDIR)/$(PREFIX)/share/perl5

SOURCES=Helpers.pm

.PHONY: install
install: $(SOURCES)
	install -d -m 0755 $(PERLDIR)/PVE/Firewall
	for i in $(SOURCES); do install -D -m 0644 $$i $(PERLDIR)/PVE/Firewall/$$i; done

clean:
