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

# the SYN_RECV timeout is written to the sysctl as configured
{
    no warnings 'redefine';
    my %written;
    local *PVE::ProcFSTools::write_proc_entry = sub { $written{ $_[0] } = $_[1] };
    my $sysctl = '/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_syn_recv';

    PVE::Firewall::update_nf_conntrack_tcp_timeout_syn_recv(
        { options => { nf_conntrack_tcp_timeout_syn_recv => 30 } });
    is($written{$sysctl}, 30, 'the configured SYN_RECV timeout is applied');

    PVE::Firewall::update_nf_conntrack_tcp_timeout_syn_recv({ options => {} });
    is($written{$sysctl}, 60, 'the default SYN_RECV timeout is 60 seconds');

    PVE::Firewall::update_nf_conntrack_tcp_timeout_syn_recv(
        { options => { nf_conntrack_tcp_timeout_syn_recv => 0 } });
    is($written{$sysctl}, 60, 'a SYN_RECV timeout of 0 falls back to the default');
}

done_testing();
