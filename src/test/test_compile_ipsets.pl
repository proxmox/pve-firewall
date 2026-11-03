#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

for my $cidr ('192.0.2.0/99', '10.0.0.0/33', '2001:db8::/129', '::/129') {
    eval { PVE::Firewall::parse_ip_or_cidr($cidr) };
    ok($@, "reject invalid CIDR $cidr");
}

my $valid = {
    '10.0.0.0/0' => ['10.0.0.0/0', 4],
    '10.0.0.1/32' => ['10.0.0.1', 4],
    '10.0.0.1/032' => ['10.0.0.1/032', 4],
    '::/0' => ['::/0', 6],
    '::1/128' => ['::1', 6],
    '::1/0128' => ['::1/0128', 6],
};
for my $cidr (sort keys $valid->%*) {
    my @parsed = eval { PVE::Firewall::parse_ip_or_cidr($cidr) };
    is_deeply(\@parsed, $valid->{$cidr}, "accept CIDR $cidr");
}

subtest 'container IP filters' => sub {
    plan skip_all => 'PVE::LXC::Config is not installed'
        if !eval { require PVE::LXC::Config; 1 };

    PVE::Firewall::set_verbose(1);
    PVE::Firewall::local_network('192.0.2.0/24');

    for my $ip (undef, 'dhcp', 'manual', '192.0.2.10/24') {
        for my $ip6 (undef, 'auto', 'dhcp', 'manual', '2001:db8::10/64') {
            my $network = 'name=eth0,hwaddr=02:00:00:00:00:01,bridge=vmbr0,firewall=1';
            $network .= ",ip=$ip" if defined($ip);
            $network .= ",ip6=$ip6" if defined($ip6);
            my $label = 'ip=' . ($ip // '<unset>') . ',ip6=' . ($ip6 // '<unset>');
            my $cluster = { aliases => {}, ipset => {}, sdn => { ipset => {} } };
            my $configs = { 100 => { vmid => 100, options => { ipfilter => 1 }, ipset => {} } };
            my $vmdata = { qemu => {}, lxc => { 100 => { net0 => $network } } };
            my @warnings;
            local $SIG{__WARN__} = sub { push @warnings, @_ };

            my $sets = PVE::Firewall::compile_ipsets($cluster, $configs, $vmdata);
            is_deeply(\@warnings, [], "$label compiles without errors");

            for my $version (4, 6) {
                my $name = "PVEFW-100-ipfilter-net0-v$version";
                ok(exists($sets->{$name}), "$label creates IPv$version set");
                my @entries = grep { /^add / } @{ $sets->{$name} // [] };
                my @expected;
                if ($version == 4) {
                    push @expected, "add $name 192.0.2.10"
                        if defined($ip) && $ip eq '192.0.2.10/24';
                } else {
                    push @expected, "add $name 2001:db8::10"
                        if defined($ip6) && $ip6 eq '2001:db8::10/64';
                    push @expected, "add $name fe80::/10 nomatch", "add $name fe80::ff:fe00:1";
                }
                is_deeply(\@entries, \@expected, "$label IPv$version filter addresses");
            }
        }
    }
};

subtest 'entries for the same network are merged in the form the kernel stores' => sub {
    PVE::Firewall::local_network('192.0.2.0/24');

    my $cluster = {
        aliases => {
            net4 => { name => 'net4', cidr => '192.0.2.5/24', ipversion => 4 },
            net6 => { name => 'net6', cidr => '2001:DB8::1:2/64', ipversion => 6 },
        },
        ipset => {
            test => [
                { cidr => '192.0.2.0/24' },
                { cidr => 'net4', nomatch => 1 },
                { cidr => '198.51.100.7/32' },
                { cidr => 'net6' },
                { cidr => '2001:db8::/64', nomatch => 1 },
                { cidr => '2001:db8::7/128' },
            ],
        },
        sdn => { ipset => {} },
    };
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    my $sets = PVE::Firewall::compile_ipsets($cluster, {}, { qemu => {}, lxc => {} });
    is_deeply(\@warnings, [], 'compiles without errors');

    my %entries = map {
        my $name = "PVEFW-0-test-v$_";
        ($_ => [map { s/^add \Q$name\E //r } grep { /^add / } ($sets->{$name} // [])->@*]);
    } (4, 6);
    is_deeply(
        $entries{4},
        ['192.0.2.0/24 nomatch', '198.51.100.7'],
        'IPv4 host bits are masked and the last entry for a network wins',
    );
    is_deeply(
        $entries{6},
        ['2001:db8::/64 nomatch', '2001:db8::7'],
        'IPv6 host bits are masked and the last entry for a network wins',
    );
};

done_testing();
