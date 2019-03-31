VERSION=3.0
PKGREL=18

PACKAGE=pve-firewall

BUILDDIR ?= ${PACKAGE}-${VERSION}

ARCH:=$(shell dpkg-architecture -qDEB_BUILD_ARCH)
GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${VERSION}-${PKGREL}_${ARCH}.deb
DEB2=${PACKAGE}-dbgsym_${VERSION}-${PKGREL}_${ARCH}.deb
DEBS=$(DEB) $(DEB2)

all: $(DEBS)

.PHONY: dinstall
dinstall: deb
	dpkg -i $(DEBS)

${BUILDDIR}:
	rm -rf ${BUILDDIR}
	rsync -a  src/ debian ${BUILDDIR}
	echo "git clone git://git.proxmox.com/git/pve-firewall.git\\ngit checkout ${GITVERSION}" > ${BUILDDIR}/debian/SOURCE

.PHONY: deb
deb: $(DEBS)
$(DEB2): $(DEB)
$(DEB): ${BUILDDIR} check
	cd ${BUILDDIR}; dpkg-buildpackage -b -us -uc
	lintian ${DEBS}

.PHONY: check
check:
	make -C test check

.PHONY: clean distclean
distclean: clean
clean:
	make -C src clean
	make -C test clean
	rm -rf *~ debian/*~ example/*~ *.deb *.changes *.buildinfo ${BUILDDIR} ${PACKAGE}-*.tar.gz

.PHONY: upload
upload: $(DEBS)
	tar cf - $(DEBS) | ssh repoman@repo.proxmox.com -- upload --product pve --dist stretch --arch ${ARCH}
