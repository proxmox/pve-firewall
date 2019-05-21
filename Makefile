include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=pve-firewall

BUILDDIR ?= ${PACKAGE}-${DEB_VERSION_UPSTREAM}
GITVERSION:=$(shell git rev-parse HEAD)

DEB=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}_${DEB_BUILD_ARCH}.deb
DSC=${PACKAGE}_${DEB_VERSION_UPSTREAM_REVISION}.dsc
DEB2=${PACKAGE}-dbgsym_${DEB_VERSION_UPSTREAM_REVISION}_${DEB_BUILD_ARCH}.deb
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

.PHONY: dsc
dsc: ${DSC}
${DSC}: ${BUILDDIR}
	cd ${BUILDDIR}; dpkg-buildpackage -S -us -uc -d
	lintian ${DSC}

.PHONY: check
check:
	make -C test check

.PHONY: clean distclean
distclean: clean
clean:
	make -C src clean
	make -C test clean
	rm -rf *~ debian/*~ example/*~ *.deb *.changes *.buildinfo ${BUILDDIR} ${PACKAGE}*.tar.gz *.dsc

.PHONY: upload
upload: $(DEBS)
	tar cf - $(DEBS) | ssh repoman@repo.proxmox.com -- upload --product pve --dist stretch --arch ${DEB_BUILD_ARCH}
