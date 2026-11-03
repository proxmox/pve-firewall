#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

my @cases = (
    [\&PVE::Firewall::pve_verify_ip_or_cidr, '192.0.2.1/24'],
    [\&PVE::Firewall::pve_verify_ip_or_cidr, '2001:db8::1/64'],
    [\&PVE::Firewall::pve_verify_ip_or_cidr_or_alias, 'guest/example'],
    [\&PVE::Firewall::parse_ip_or_cidr, '192.0.2.0/24'],
    [\&PVE::Firewall::parse_ip_or_cidr, '2001:db8::1'],
    [\&PVE::Firewall::parse_address_list, '192.0.2.0/24'],
    [\&PVE::Firewall::parse_address_list, 'dc/example'],
    [\&PVE::Firewall::parse_address_list, '+guest/example'],
);

for my $verify (
    \&PVE::Firewall::pve_fw_verify_sport_spec, \&PVE::Firewall::pve_fw_verify_dport_spec,
) {
    push @cases, map { [$verify, $_] } ('0', '123', '123:456', '123,456', 'ssh');
}

for my $case (@cases) {
    my ($verify, $input) = @$case;
    eval { $verify->($input) };
    is($@, '', "accept $input");
    eval { $verify->("$input\n") };
    ok($@, "reject trailing newline after $input");
}

done_testing();
