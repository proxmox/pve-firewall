
PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/bin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc
MAN1DIR=${MANDIR}/man1/
PERLDIR=${PREFIX}/share/perl5

LIB_SOURCES=			\
	Firewall.pm

all:

.PHONY: install
install:
	install -d -m 0755 ${DESTDIR}/${SBINDIR}
	install -m 0755 pvefw ${DESTDIR}/${SBINDIR}
	install -d -m 0755 ${DESTDIR}${PERLDIR}/PVE
	for i in ${LIB_SOURCES}; do install -D -m 0644 PVE/$$i ${DESTDIR}${PERLDIR}/PVE/$$i; done


.PHONY: clean
clean: 	
	rm -rf *~

.PHONY: distclean
distclean: clean

