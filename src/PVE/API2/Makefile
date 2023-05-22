DESTDIR=
PREFIX=/usr
PERLDIR=$(DESTDIR)/$(PREFIX)/share/perl5

all:

.PHONY: install
install:
	install -d -m 0755 $(PERLDIR)/PVE/API2
	make -C Firewall install

.PHONY: clean
clean:
	rm -rf *~
	make -C Firewall clean
