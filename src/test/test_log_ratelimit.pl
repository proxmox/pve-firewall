#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use Test::More;

use PVE::Firewall;
use PVE::JSONSchema;

my $parse = sub { PVE::JSONSchema::parse_property_string('pve-fw-log-ratelimit', $_[0]) };

for my $value (
    '1',
    '0,rate=1/day',
    'enable=1,rate=10/minute,burst=20',
    '1,rate=10000/second,burst=10000',
    '1,rate=1/day,burst=1',
    '1,rate=1/hour,burst=37',
    '1,rate=2/day,burst=3',
) {
    ok(eval { $parse->($value) }, "accepts '$value'") or diag($@);
}

# rejected by iptables, or bursts of more than about 37 hours, which legacy iptables either rejects
# or applies with a wrong burst
for my $value (
    '1,rate=10001/second',
    '1,burst=10001',
    '1,rate=1/day',
    '1,rate=1/day,burst=2',
    '1,rate=2/day',
    '1,rate=1/hour,burst=38',
) {
    ok(!eval { $parse->($value) }, "rejects '$value'");
}

done_testing();
