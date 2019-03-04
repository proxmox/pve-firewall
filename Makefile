VERSION=3.0
PKGREL=18

PACKAGE=pve-firewall

PREFIX=/usr
BINDIR=${PREFIX}/bin
SBINDIR=${PREFIX}/sbin
MANDIR=${PREFIX}/share/man
DOCDIR=${PREFIX}/share/doc
MAN1DIR=${MANDIR}/man1/
PERLDIR=${PREFIX}/share/perl5

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb
DEB2=${PACKAGE}-dbgsym_${VERSION}-${PKGREL}_${ARCH}.deb
DEBS=$(DEB) $(DEB2)

all: $(DEBS)

.PHONY: dinstall
dinstall: deb
	dpkg -i $(DEBS)


.PHONY: deb
deb: $(DEBS)
$(DEB2): $(DEB)
$(DEB): src test debian
	make check
	rm -rf build
	rsync -a src/ build
	rsync -a debian/ build/debian
	echo "git clone git://git.proxmox.com/git/pve-firewall.git\\ngit checkout ${GITVERSION}" > build/debian/SOURCE
	# install
	cd build; dpkg-buildpackage -b -us -uc
	lintian ${DEBS}

.PHONY: check
check: 
	make -C test check

.PHONY: clean
clean: 	
	make -C src clean
	make -C test clean
	rm -rf *~ debian/*~ example/*~ *.deb *.changes *.buildinfo build ${PACKAGE}-*.tar.gz

.PHONY: distclean
distclean: clean


.PHONY: upload
upload: $(DEBS)
	tar cf - $(DEBS) | ssh repoman@repo.proxmox.com -- upload --product pve --dist stretch --arch ${ARCH}
