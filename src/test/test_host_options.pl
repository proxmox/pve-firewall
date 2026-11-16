#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;
use PVE::JSONSchema;

# the SYN flood protection passes these to a hashlimit match, and the timeout to its sysctl
for my $line (
    'protection_synflood_rate: 1000000',
    'protection_synflood_burst: 1000000',
    'nf_conntrack_tcp_timeout_syn_recv: 2147483',
    'nf_conntrack_max: 1',
) {
    ok(eval { PVE::Firewall::parse_hostfw_option($line) }, "parses '$line'") or diag($@);
}

for my $line (
    'protection_synflood_rate: 1000001',
    'protection_synflood_burst: 1000001',
    'nf_conntrack_tcp_timeout_syn_recv: 2147484',
) {
    ok(!eval { PVE::Firewall::parse_hostfw_option($line) }, "rejects '$line'");
}

my $schema = { type => 'object', properties => $PVE::Firewall::host_option_properties };
for my $option ('protection_synflood_rate', 'protection_synflood_burst') {
    ok(
        eval { PVE::JSONSchema::validate({ $option => 1000000 }, $schema) },
        "API accepts $option 1000000",
    );
    ok(
        !eval { PVE::JSONSchema::validate({ $option => 1000001 }, $schema) },
        "API rejects $option 1000001",
    );
}

done_testing();
