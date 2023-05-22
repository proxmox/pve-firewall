DESTDIR=
PREFIX= /usr
PERLDIR=$(DESTDIR)/$(PREFIX)/share/perl5

LIB_SOURCES=			\
	FirewallSimulator.pm	\
	Firewall.pm

all:

.PHONY: install
install:
	install -d -m 0755 $(PERLDIR)/PVE
	for i in $(LIB_SOURCES); do install -D -m 0644 $$i $(PERLDIR)/PVE/$$i; done
	make -C API2 install
	make -C Service install
	make -C Firewall install

.PHONY: clean
clean:
	rm -rf *~
	make -C API2 clean
	make -C Service clean
	make -C Firewall clean
