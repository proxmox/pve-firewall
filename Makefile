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

.PHONY: dinstall
dinstall: deb
	dpkg -i $(DEBS)

$(BUILDDIR):
	rm -rf $(BUILDDIR)
	rsync -a  src/ debian $(BUILDDIR)
	echo "git clone git://git.proxmox.com/git/pve-firewall.git\\ngit checkout $(GITVERSION)" > $(BUILDDIR)/debian/SOURCE

.PHONY: deb
deb: $(DEBS)
$(DEB2): $(DEB)
$(DEB): $(BUILDDIR) check
	cd $(BUILDDIR); dpkg-buildpackage -b -us -uc
	lintian $(DEBS)

.PHONY: dsc
dsc: $(DSC)
$(DSC): $(BUILDDIR)
	cd $(BUILDDIR); dpkg-buildpackage -S -us -uc -d
	lintian $(DSC)

.PHONY: check
check:
	make -C test check

.PHONY: clean distclean
distclean: clean
clean:
	make -C src clean
	make -C test clean
	rm -rf *.deb *.dsc *.changes *.build *.buildinfo $(PACKAGE)-[0-9]*/ $(PACKAGE)*.tar*

.PHONY: upload
upload: $(DEBS)
	tar cf - $(DEBS) | ssh repoman@repo.proxmox.com -- upload --product pve --dist bullseye --arch $(DEB_HOST_ARCH)
