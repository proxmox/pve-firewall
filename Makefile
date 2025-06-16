include /usr/share/dpkg/pkg-info.mk
include /usr/share/dpkg/architecture.mk

PACKAGE=pve-firewall

BUILDDIR ?= $(PACKAGE)-$(DEB_VERSION)
GITVERSION:=$(shell git rev-parse HEAD)

DEB=$(PACKAGE)_$(DEB_VERSION)_$(DEB_HOST_ARCH).deb
DSC=$(PACKAGE)_$(DEB_VERSION).dsc
DEB2=$(PACKAGE)-dbgsym_$(DEB_VERSION)_$(DEB_HOST_ARCH).deb
DEBS=$(DEB) $(DEB2)

all: $(DEBS)

.PHONY: tidy
tidy:
	git ls-files ':*.p[ml]'| xargs -n4 -P0 proxmox-perltidy

.PHONY: dinstall
dinstall: $(DEB)
	dpkg -i $<

$(BUILDDIR):
	rm -rf $(BUILDDIR)
	rsync -a  src/ debian $(BUILDDIR)
	echo "git clone git://git.proxmox.com/git/pve-firewall.git\\ngit checkout $(GITVERSION)" > $(BUILDDIR)/debian/SOURCE

.PHONY: deb
deb: $(DEBS)
$(DEB2): $(DEB)
$(DEB): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEBS)

.PHONY: dsc
dsc:
	rm -rf $(DSC) $(BUILDDIR)
	$(MAKE) $(DSC)
	lintian $(DSC)

$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc -d

sbuild: $(DSC)
	sbuild $(DSC)

check:
	make -C test check

.PHONY: clean distclean
distclean: clean
clean:
	make -C src clean
	make -C test clean
	rm -rf *.deb *.dsc *.changes *.build *.buildinfo $(PACKAGE)-[0-9]*/ $(PACKAGE)*.tar*

.PHONY: upload
upload: UPLOAD_DIST ?= $(DEB_DISTRIBUTION)
upload: $(DEBS)
	tar cf - $(DEBS) | ssh repoman@repo.proxmox.com -- upload --product pve --dist $(UPLOAD_DIST) --arch $(DEB_HOST_ARCH)
