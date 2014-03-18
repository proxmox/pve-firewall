
LIB_SOURCES=			\
	Firewall.pm

all:

.PHONY: install
install:
	install -d -m 0755 ${DESTDIR}${PERLDIR}/PVE
	for i in ${LIB_SOURCES}; do install -D -m 0644 $$i ${DESTDIR}${PERLDIR}/PVE/$$i; done	
	make -C API2 install

.PHONY: clean
clean:
	rm -rf *~
	make -C API2 clean