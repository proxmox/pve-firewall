#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

plan(skip_all => 'PVE::QemuServer::Network is not installed')
    if !eval { require PVE::QemuServer::Network; 1 };

my $have_lxc = eval { require PVE::LXC::Config; 1 };

PVE::Firewall::set_verbose(1);

sub compile_arp_sources {
    my ($entries, $lxc_ip, $ipfilter) = @_;

    my $cluster = {
        options => {},
        aliases => { dcalias => { name => 'dcalias', cidr => '192.0.2.2', ipversion => 4 } },
    };
    my $vmfw_conf = {
        vmid => 100,
        options => { enable => 1 },
        aliases =>
            { guestalias => { name => 'guestalias', cidr => '192.0.2.1', ipversion => 4 } },
        ipset => defined($entries) ? { 'ipfilter-net0' => $entries } : {},
    };
    my $vmdata = { qemu => {}, lxc => {} };
    my $iface = 'tap100i0';
    if (defined($lxc_ip)) {
        $iface = 'veth100i0';
        $vmfw_conf->{options}->{ipfilter} = $ipfilter // 1;
        $vmdata->{lxc}->{100} =
            { net0 => "name=eth0,bridge=vmbr0,hwaddr=02:00:00:00:00:01,firewall=1,ip=$lxc_ip" };
    } else {
        $vmdata->{qemu}->{100} = { net0 => 'virtio=02:00:00:00:00:01,bridge=vmbr0,firewall=1' };
    }

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    my $ruleset =
        PVE::Firewall::compile_ebtables_filter($cluster, {}, { 100 => $vmfw_conf }, $vmdata);

    ok(exists($ruleset->{"$iface-OUT"}), 'guest keeps its layer-2 filter');
    my $arp_rules = $ruleset->{"$iface-OUT-ARP"} // [];
    my @sources = map { /--arp-ip-src (\S+) -j RETURN/ ? $1 : () } $arp_rules->@*;
    my @rules = map { /--arp-ip-src (\S+) -j (\S+)/ ? "$2 $1" : () } $arp_rules->@*;

    return (\@sources, \@warnings, \@rules);
}

subtest 'aliases are resolved' => sub {
    my ($sources, $warnings) = compile_arp_sources([
        { cidr => '192.0.2.10' },
        { cidr => 'guestalias' },
        { cidr => 'guest/guestalias' },
        { cidr => 'dc/dcalias' },
        { cidr => 'dcalias' },
    ]);
    is_deeply(
        $sources,
        ['192.0.2.10', '192.0.2.1', '192.0.2.2'],
        'ARP filter contains each resolved address once',
    );
    is_deeply($warnings, [], 'no warnings');
};

subtest 'entries flagged by the parser are skipped' => sub {
    my ($sources, $warnings) = compile_arp_sources([
        { cidr => 'c', errors => { cidr => 'invalid' } }, { cidr => '192.0.2.10' },
    ]);
    is_deeply($sources, ['192.0.2.10'], 'valid entry is kept');
    is_deeply($warnings, [], 'no warnings');
};

subtest 'unresolvable entries are skipped with context' => sub {
    my ($sources, $warnings) = compile_arp_sources([
        { cidr => 'missing' }, { cidr => '192.0.2.10' },
    ]);
    is_deeply($sources, ['192.0.2.10'], 'valid entry is kept');
    is(scalar($warnings->@*), 1, 'one warning');
    like(
        $warnings->[0] // '',
        qr/^100: ipfilter-net0: skipping 'missing': /,
        'warning names guest, ipset and entry',
    );
};

subtest 'nomatch entries are excluded' => sub {
    my (undef, $warnings, $rules) = compile_arp_sources([
        { cidr => '192.0.2.0/24' }, { cidr => '192.0.2.5', nomatch => 1 },
    ]);
    is_deeply(
        $rules,
        ['DROP 192.0.2.5', 'RETURN 192.0.2.0/24'],
        'excluded address is dropped before the allowed network',
    );
    is_deeply($warnings, [], 'no warnings');
};

subtest 'more specific entries take precedence over nomatch networks' => sub {
    my (undef, $warnings, $rules) = compile_arp_sources([
        { cidr => '192.0.2.0/24', nomatch => 1 }, { cidr => '192.0.2.5' },
    ]);
    is_deeply(
        $rules,
        ['RETURN 192.0.2.5', 'DROP 192.0.2.0/24'],
        'allowed address is returned before the excluded network',
    );
    is_deeply($warnings, [], 'no warnings');
};

subtest 'entries with the same prefix length keep their order' => sub {
    my (undef, $warnings, $rules) = compile_arp_sources([
        { cidr => '192.0.2.20' }, { cidr => '192.0.2.0/24' }, { cidr => '192.0.2.3' },
    ]);
    is_deeply(
        $rules,
        ['RETURN 192.0.2.20', 'RETURN 192.0.2.3', 'RETURN 192.0.2.0/24'],
        'ties are not reordered',
    );
    is_deeply($warnings, [], 'no warnings');
};

subtest 'the last entry for an address wins, as in the IP set' => sub {
    my (undef, $warnings, $rules) = compile_arp_sources([
        { cidr => 'guestalias' }, { cidr => '192.0.2.1', nomatch => 1 },
    ]);
    is_deeply($rules, ['DROP 192.0.2.1'], 'nomatch entry after the alias excludes the address');
    is_deeply($warnings, [], 'no warnings');

    (undef, $warnings, $rules) = compile_arp_sources([
        { cidr => '192.0.2.1', nomatch => 1 }, { cidr => 'guestalias' },
    ]);
    is_deeply($rules, ['RETURN 192.0.2.1'], 'alias after the nomatch entry allows the address');
    is_deeply($warnings, [], 'no warnings');
};

subtest 'entries for the same network are merged, as in the IP set' => sub {
    my (undef, $warnings, $rules) = compile_arp_sources([
        { cidr => '192.0.2.0/24' }, { cidr => '192.0.2.5/24', nomatch => 1 },
    ]);
    is_deeply($rules, ['DROP 192.0.2.0/24'], 'host bits are masked and the last entry wins');
    is_deeply($warnings, [], 'no warnings');
};

subtest 'the configured container IP wins over a nomatch entry, as in the IP set' => sub {
    plan(skip_all => 'PVE::LXC::Config is not installed') if !$have_lxc;

    my (undef, $warnings, $rules) = compile_arp_sources(
        [{ cidr => '192.0.2.0/24' }, { cidr => '192.0.2.5', nomatch => 1 }],
        '192.0.2.5/24',
    );
    is_deeply(
        $rules,
        ['RETURN 192.0.2.5', 'RETURN 192.0.2.0/24'],
        'container IP is allowed despite the nomatch entry',
    );
    is_deeply($warnings, [], 'no warnings');
};

subtest 'only literal container addresses are allowed' => sub {
    plan(skip_all => 'PVE::LXC::Config is not installed') if !$have_lxc;

    for my $ip ('dhcp', 'manual') {
        my (undef, $warnings, $rules) = compile_arp_sources(undef, $ip);
        is_deeply($rules, [], "no ARP source for ip=$ip");
        is_deeply($warnings, [], 'no warnings');
    }

    my (undef, $warnings, $rules) = compile_arp_sources(undef, '192.0.2.5/24');
    is_deeply($rules, ['RETURN 192.0.2.5'], 'static address is used without its prefix');
    is_deeply($warnings, [], 'no warnings');
};

subtest 'an ipfilter set allows the container IP without the ipfilter option' => sub {
    plan(skip_all => 'PVE::LXC::Config is not installed') if !$have_lxc;

    my (undef, $warnings, $rules) = compile_arp_sources([], '192.0.2.5/24', 0);
    is_deeply($rules, ['RETURN 192.0.2.5'], 'empty set allows the container IP');
    is_deeply($warnings, [], 'no warnings');

    (undef, $warnings, $rules) =
        compile_arp_sources([{ cidr => '192.0.2.10' }], '192.0.2.5/24', 0);
    is_deeply($rules, ['RETURN 192.0.2.10', 'RETURN 192.0.2.5'], 'set entries are kept');
    is_deeply($warnings, [], 'no warnings');

    (undef, $warnings, $rules) = compile_arp_sources(undef, '192.0.2.5/24', 0);
    is_deeply($rules, [], 'no ARP filter without the option or a set');
    is_deeply($warnings, [], 'no warnings');
};

done_testing();
