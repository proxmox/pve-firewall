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

# the chain names of a group are limited to 28 characters, which group names fit into
for my $env ('vm', 'host') {
    my $rule = PVE::Firewall::parse_fw_rule('test', 'GROUP ' . 'g' x 18, {}, {}, $env);
    ok(!$rule->{errors}, "$env: references to groups with 18 characters are valid");

    $rule = PVE::Firewall::parse_fw_rule('test', 'GROUP ' . 'g' x 19, {}, {}, $env);
    ok($rule->{errors}->{action}, "$env: references to groups with 19 characters are invalid");
}

# a group whose chains cannot be created, referenced by a guest
my $long_group = 'g' x 20;
my $vmfw_conf = {
    options => { enable => 1 },
    rules => [
        { type => 'group', action => $long_group, enable => 1 },
        { type => 'in', action => 'ACCEPT', enable => 1, proto => 'tcp', dport => '80' },
    ],
};

$ruleset = {};
PVE::Firewall::ruleset_create_chain($ruleset, 'PVEFW-FWBR-IN');
@warnings = ();
{
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    eval {
        PVE::Firewall::generate_tap_rules_direction(
            $ruleset, $cluster_conf, 'tap100i0', 'net0', undef, $vmfw_conf, 100, 'IN', 4,
        );
    };
    is($@, '', 'a group reference that cannot be generated does not abort the guest');
}

like(
    join('', @warnings),
    qr/^security group '$long_group': Invalid chain name/m,
    'the failing group reference is reported',
);
ok(grep({ /--dport 80/ } @{ $ruleset->{'tap100i0-IN'} }), 'the other guest rules are generated');
ok(grep({ /-j tap100i0-IN/ } @{ $ruleset->{'PVEFW-FWBR-IN'} }), 'the guest chain is plugged');

done_testing();
