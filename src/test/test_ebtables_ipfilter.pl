#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

plan(skip_all => 'PVE::QemuServer::Network is not installed')
    if !eval { require PVE::QemuServer::Network; 1 };

PVE::Firewall::set_verbose(1);

sub compile_arp_sources {
    my ($entries) = @_;

    my $cluster = {
        options => {},
        aliases => { dcalias => { name => 'dcalias', cidr => '192.0.2.2', ipversion => 4 } },
    };
    my $vmfw_conf = {
        vmid => 100,
        options => { enable => 1 },
        aliases =>
            { guestalias => { name => 'guestalias', cidr => '192.0.2.1', ipversion => 4 } },
        ipset => { 'ipfilter-net0' => $entries },
    };
    my $vmdata = {
        qemu => { 100 => { net0 => 'virtio=02:00:00:00:00:01,bridge=vmbr0,firewall=1' } },
        lxc => {},
    };

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    my $ruleset =
        PVE::Firewall::compile_ebtables_filter($cluster, {}, { 100 => $vmfw_conf }, $vmdata);

    ok(exists($ruleset->{'tap100i0-OUT'}), 'guest keeps its layer-2 filter');
    my @sources = map { /--arp-ip-src (\S+)/ ? $1 : () } ($ruleset->{'tap100i0-OUT-ARP'} // [])->@*;

    return (\@sources, \@warnings);
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
        ['192.0.2.10', '192.0.2.1', '192.0.2.1', '192.0.2.2', '192.0.2.2'],
        'ARP filter contains resolved addresses',
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

done_testing();
