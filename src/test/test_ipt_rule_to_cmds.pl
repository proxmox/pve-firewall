#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;

my $protocol_ids = {
    tcp => 6,
    udp => 17,
    sctp => 132,
    udplite => 136,
    icmp => 1,
    icmpv6 => 58,
    'ipv6-icmp' => 58,
};

for my $ipversion (4, 6) {
    for my $proto ('udplite', '136') {
        my $id = $protocol_ids->{$proto} // $proto;
        for my $sport (undef, '0', '1234', '1234:1236', '1234,1236') {
            for my $dport (undef, '0', '4321', '4321:4323', '4321,4323') {
                my $line = "IN ACCEPT -p $proto";
                $line .= " -sport $sport" if defined($sport);
                $line .= " -dport $dport" if defined($dport);

                my $rule = PVE::Firewall::parse_fw_rule('test', $line, {}, {}, 'host');
                ok(!$rule->{errors}, "IPv$ipversion: validate $line");

                my $expected = "-A TEST -p $id";
                $expected .= " --match multiport --dports $dport" if defined($dport);
                $expected .= " --match multiport --sports $sport" if defined($sport);
                $expected .= ' -j ACCEPT';

                is_deeply(
                    [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', $ipversion, {}, {})],
                    [$expected],
                    "IPv$ipversion: compile $line",
                );
            }
        }
    }

    for my $proto ('tcp', '6', 'udp', '17') {
        my $id = $protocol_ids->{$proto} // $proto;
        my $rule = { proto => $proto, sport => '1234', dport => '4321', action => 'ACCEPT' };
        is_deeply(
            [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', $ipversion, {}, {})],
            ["-A TEST -p $id --sport 1234 --dport 4321 -j ACCEPT"],
            "IPv$ipversion: $proto single ports do not need multiport",
        );
    }
}

for my $proto ('icmp', 'icmpv6', 'ipv6-icmp') {
    my $id = $protocol_ids->{$proto};
    my $version = $proto eq 'icmp' ? 4 : 6;
    my $type = $proto eq 'icmp' ? 'icmp-type' : 'icmpv6-type';
    my $rule = PVE::Firewall::parse_fw_rule('test', "IN ACCEPT -p $proto -dport 0", {}, {}, 'host');
    ok(!$rule->{errors}, "$proto accepts type zero");
    is_deeply(
        [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', $version, {}, {})],
        ["-A TEST -p $id -m $proto --$type 0 -j ACCEPT"],
        "$proto preserves type zero restriction",
    );

    $rule = PVE::Firewall::parse_fw_rule(
        'test',
        "IN ACCEPT -p $proto -dport echo-request",
        {},
        {},
        'host',
    );
    ok(!$rule->{errors}, "$proto accepts type name in dport");
    is_deeply(
        [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', $version, {}, {})],
        ["-A TEST -p $id -m $proto --$type echo-request -j ACCEPT"],
        "$proto matches type name from dport",
    );
}

for my $case (
    [4, '-p 1 -m icmp --icmp-type echo-request'],
    [6, '-p 58 -m icmpv6 --icmpv6-type echo-request'],
) {
    my ($version, $match) = @$case;
    my $rule = PVE::Firewall::parse_fw_rule('test', 'IN Ping(ACCEPT)', {}, {}, 'host');
    ok(!$rule->{errors}, "IPv$version: validate Ping macro");

    my $ruleset = {};
    PVE::Firewall::ruleset_create_chain($ruleset, 'TEST');
    PVE::Firewall::ruleset_generate_rule($ruleset, 'TEST', $version, $rule, {}, {});
    is_deeply(
        $ruleset->{TEST},
        ["-A TEST $match -j ACCEPT"],
        "IPv$version: Ping macro matches type name from dport",
    );
}

for my $line (
    'IN ACCEPT -p icmp -dport neighbor-solicitation',
    'IN ACCEPT -p icmpv6 -dport timestamp-request',
    'IN ACCEPT -p ipv6-icmp -dport timestamp-request',
    'IN ACCEPT -p icmp -dport 0:8',
    'IN ACCEPT -p icmpv6 -dport 256',
    'IN ACCEPT -p icmp -dport 08',
    'IN ACCEPT -p icmpv6 -dport 010',
    'IN ACCEPT -p ipv6-icmp -dport 010',
) {
    my $rule = PVE::Firewall::parse_fw_rule('test', $line, {}, {}, 'host');
    ok($rule->{errors}->{dport}, "rejects $line");
}

for my $proto ('tcp', 'udp', 'sctp', 'udplite', '136') {
    my $id = $protocol_ids->{$proto} // $proto;
    my $rule = { proto => $proto, sport => '0', dport => '0', action => 'ACCEPT' };
    my $ports =
        $proto eq 'udplite' || $proto eq '136'
        ? '--match multiport --dports 0 --match multiport --sports 0'
        : '--sport 0 --dport 0';
    is_deeply(
        [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', 4, {}, {})],
        ["-A TEST -p $id $ports -j ACCEPT"],
        "$proto preserves zero source and destination ports",
    );

    $rule->{sport} = 'ssh';
    $rule->{dport} = 'bootps';
    $ports =
        $proto eq 'udplite' || $proto eq '136'
        ? '--match multiport --dports 67 --match multiport --sports 22'
        : '--sport 22 --dport 67';
    is_deeply(
        [PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', 4, {}, {})],
        ["-A TEST -p $id $ports -j ACCEPT"],
        "$proto resolves port aliases independently of the service protocol",
    );
}

for my $proto ('udplite', '136') {
    for my $field ('sport', 'dport') {
        for my $port ('65536', '1236:1234', '1234,') {
            my $rule = { proto => $proto, $field => $port, action => 'ACCEPT' };
            eval { PVE::Firewall::ipt_rule_to_cmds($rule, 'TEST', 4, {}, {}) };
            ok($@, "$proto rejects invalid $field $port");
        }
    }
}

done_testing();
