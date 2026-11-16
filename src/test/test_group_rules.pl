#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

# rules are built directly, since verify_rule() rejects the failing one when parsing
my $cluster_conf = {
    groups => {
        grp => [
            { type => 'in', action => 'ACCEPT', enable => 1, proto => 'icmp', dport => '0:8' },
            { type => 'in', action => 'ACCEPT', enable => 1, proto => 'tcp', dport => '22' },
            { type => 'out', action => 'DROP', enable => 1, proto => 'tcp', dport => '23' },
        ],
    },
};

my $ruleset = {};
my @warnings;
{
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    eval { PVE::Firewall::generate_group_rules($ruleset, $cluster_conf, 'grp', 4) };
    is($@, '', 'a rule that cannot be generated does not abort the group');
}

like(
    join('', @warnings),
    qr/^security group 'grp': skipping rule 0: /,
    'the failing rule is reported',
);
ok(grep({ /--dport 22/ } @{ $ruleset->{'GROUP-grp-IN'} }), 'the other inbound rules are generated');
ok(grep({ /--dport 23/ } @{ $ruleset->{'GROUP-grp-OUT'} }), 'the outbound chain is generated');
ok(!grep({ /icmp/ } @{ $ruleset->{'GROUP-grp-IN'} }), 'the failing rule is skipped');

done_testing();
