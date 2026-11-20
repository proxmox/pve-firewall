TESTS = test_parse_address_list test_ipt_rule_to_cmds test_parameter_newlines test_compile_ipsets test_ebtables_ipfilter test_simulator_protocols test_interface_names test_restore_errors test_group_rules test_log_ratelimit test_host_options

CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
CFLAGS+=$(shell pkg-config libnetfilter_log libnetfilter_conntrack glib-2.0 --libs --cflags)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

.PHONY: all test $(TESTS) run_test_pvefw_logger clean
all: test

test: $(TESTS) run_test_pvefw_logger

$(TESTS): %: %.pl
	./$<

test_pvefw_logger: test_pvefw_logger.c ../pvefw-logger.c
	gcc -Wall -Werror -Wno-unused-function test_pvefw_logger.c -o test_pvefw_logger -std=gnu99 $(CFLAGS) $(LDFLAGS) -Wl,--wrap=nfct_snprintf

run_test_pvefw_logger: test_pvefw_logger
	./test_pvefw_logger

clean:
	rm -f test_pvefw_logger
