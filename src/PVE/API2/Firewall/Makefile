DESTDIR=
PREFIX=/usr
PERLDIR=$(DESTDIR)/$(PREFIX)/share/perl5

LIB_SOURCES=			\
	Aliases.pm		\
	Helpers.pm		\
	IPSet.pm		\
	Rules.pm		\
	Cluster.pm		\
	Host.pm			\
	VM.pm			\
	Vnet.pm			\
	Groups.pm

all:

.PHONY: install
install:
	install -d -m 0755 $(PERLDIR)/PVE/API2/Firewall
	for i in $(LIB_SOURCES); do install -D -m 0644 $$i $(PERLDIR)/PVE/API2/Firewall/$$i; done	


.PHONY: clean
clean:
	rm -rf *~
