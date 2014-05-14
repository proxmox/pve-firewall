#!/usr/bin/perl

use lib '../src';
use strict;
use warnings;
use Data::Dumper;
use PVE::Firewall;

my $mark;
my $trace;

my $outside_iface = 'eth0';
my $outside_bridge = 'vmbr0';

my $debug = 0;

sub add_trace {
    my ($text) = @_;

    if ($debug) {
	print $text;
    } else {
	$trace .= $text;
    }
}

sub rule_match {
    my ($chain, $rule, $pkg) = @_;

    $rule =~ s/^-A $chain // || die "got strange rule: $rule";

    if ($rule =~ s/^-m conntrack\s*//) {
	return undef; # simply ignore
    }

    if ($rule =~ s/^-m addrtype\s*//) {
	return undef; # simply ignore
    }

    if ($rule =~ s/^-i (\S+)\s*//) {
	die "missing iface_in" if !$pkg->{iface_in};
	return undef if $pkg->{iface_in} ne $1; # no match
    }
    if ($rule =~ s/^-o (\S+)\s*//) {
	die "missing iface_out" if !$pkg->{iface_out};
	return undef if $pkg->{iface_out} ne $1; # no match
    }

    if ($rule =~ s/^-p (tcp|udp)\s*//) {
	die "missing proto" if !$pkg->{proto};
	return undef if $pkg->{proto} ne $1; # no match
    }

    if ($rule =~ s/^--dport (\d+):(\d+)\s*//) {
	die "missing dport" if !$pkg->{dport};
	return undef if ($pkg->{dport} < $1) || ($pkg->{dport} > $2); # no match
    }

    if ($rule =~ s/^--dport (\d+)\s*//) {
	die "missing dport" if !$pkg->{dport};
	return undef if $pkg->{dport} != $1; # no match
    }

    if ($rule =~ s/^-s (\S+)\s*//) {
	die "missing source" if !$pkg->{source};
	return undef if $pkg->{source} ne $1; # no match
    }
    
    if ($rule =~ s/^-d (\S+)\s*//) {
	die "missing destination" if !$pkg->{dest};
	return undef if $pkg->{dest} ne $1; # no match
    }

    if ($rule =~ s/^-m mac ! --mac-source (\S+)\s*//) {
	die "missing source mac" if !$pkg->{mac_source};
	return undef if $pkg->{mac_source} eq $1; # no match
    }

    if ($rule =~ s/^-m physdev --physdev-is-bridged --physdev-in (\S+)\s*//) {
	my $devre = $1;
	$devre =~ s/\+/\.\*/;
	return undef if !$pkg->{physdev_in};
	return undef if $pkg->{physdev_in} !~ m/^${devre}$/;
    }

    if ($rule =~ s/^-m physdev --physdev-is-bridged --physdev-out (\S+)\s*//) {
	my $devre = $1;
	$devre =~ s/\+/\.\*/;
	return undef if !$pkg->{physdev_out};
	return undef if $pkg->{physdev_out} !~ m/^${devre}$/;
    }

    if ($rule =~ s/^-j MARK --set-mark (\d+)\s*$//) {
	$mark = $1;
	return undef;
    }

    if ($rule =~ s/^-j (\S+)\s*$//) {
	return (0, $1);
    }

    if ($rule =~ s/^-g (\S+)\s*$//) {
	return (1, $1);
    }

    die "unable to parse rule: $rule";
}

sub ruleset_simulate_chain {
    my ($ruleset, $chain, $pkg) = @_;

    add_trace("ENTER chain $chain\n");
    
    if ($chain eq 'PVEFW-Drop') {
	add_trace("LEAVE chain $chain\n");
	return 'DROP';
    }
    if ($chain eq 'PVEFW-reject') {
	add_trace("LEAVE chain $chain\n");
	return 'REJECT';
    }

    if ($chain eq 'PVEFW-tcpflags') {
	add_trace("LEAVE chain $chain\n");
	return undef;
    }

    my $rules = $ruleset->{$chain} ||
	die "no such chain '$chain'";

    foreach my $rule (@$rules) {
	my ($goto, $action) = rule_match($chain, $rule, $pkg);
	if (!defined($action)) {
	    add_trace("SKIP: $rule\n");
	    next;
	}
	add_trace("MATCH: $rule\n");
	
	if ($action eq 'ACCEPT' || $action eq 'DROP' || $action eq 'REJECT') {
	    add_trace("TERMINATE chain $chain: $action\n");
	    return $action;
	} elsif ($action eq 'RETURN') {
	    add_trace("RETURN FROM chain $chain\n");
	    last;
	} else {
	    if ($goto) {
		add_trace("LEAVE chain $chain - goto $action\n");
		return ruleset_simulate_chain($ruleset, $action, $pkg)
		#$chain = $action;
		#$rules = $ruleset->{$chain} || die "no such chain '$chain'";
	    } else {
		if ($action = ruleset_simulate_chain($ruleset, $action, $pkg)) {
		    return $action;
		}
		add_trace("CONTINUE chain $chain\n");
	    }
	}
    }

    add_trace("LEAVE chain $chain\n");
    if ($chain =~ m/^PVEFW-(INPUT|OUTPUT|FORWARD)$/) {
	return 'ACCEPT'; # default policy
    }

    return undef;
}

sub copy_packet {
    my ($pkg) = @_;

    my $res = {};

    while (my ($k,$v) = each %$pkg) {
	$res->{$k} = $v;
    }

    return $res;
}

# Try to simulate packet traversal inside kernel. This invokes iptable
# checks several times.
sub route_packet {
    my ($ruleset, $ipset_ruleset, $pkg, $from_info, $target, $start_state) = @_;

    my $route_state = $start_state;

    my $physdev_in;

    while ($route_state ne $target->{iface}) {

	my $chain;
	my $next_route_state;
	my $next_physdev_in;

	$pkg->{iface_in} = $pkg->{iface_out} = undef;
	$pkg->{physdev_in} = $pkg->{physdev_out} = undef;

	if ($route_state eq 'from-outside') {
	    $next_route_state = $outside_bridge || die 'internal error';
	    $next_physdev_in = $outside_iface || die 'internal error';
	} elsif ($route_state eq 'host') {

	    if ($target->{type} eq 'outside') {
		$pkg->{iface_in} = 'lo';
		$pkg->{iface_out} = $outside_bridge;
		$chain = 'PVEFW-OUTPUT';
		$next_route_state = $outside_iface
	    } elsif ($target->{type} eq 'ct') {
		$pkg->{iface_in} = 'lo';
		$pkg->{iface_out} = 'venet0';
		$chain = 'PVEFW-OUTPUT';
		$next_route_state = 'venet-in';
	    } elsif ($target->{type} eq 'vm') {
		$pkg->{iface_in} = 'lo';
		$pkg->{iface_out} = $target->{bridge} || die 'internal error';
		$chain = 'PVEFW-OUTPUT';
		$next_route_state = 'fwbr-in';
	    } else {
		die "implement me";
	    }

	} elsif ($route_state eq 'venet-out') {

	    if ($target->{type} eq 'host') {

		$chain = 'PVEFW-INPUT';
		$pkg->{iface_in} = 'venet0';
		$pkg->{iface_out} = 'lo';
		$next_route_state = 'host';

	    } elsif ($target->{type} eq 'outside') {
		
		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = 'venet0';
		$pkg->{iface_out} = $outside_bridge;
		$next_route_state = $outside_iface;

	    } elsif ($target->{type} eq 'vm') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = 'venet0';
		$pkg->{iface_out} = $target->{bridge} || die 'internal error';
		$next_route_state = 'fwbr-in';

	    } elsif ($target->{type} eq 'ct') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = 'venet0';
		$pkg->{iface_out} = 'venet0';
		$next_route_state = 'venet-in';

	    } else {
		die "implement me";
	    }

	} elsif ($route_state eq 'fwbr-out') {

	    $chain = 'PVEFW-FORWARD';
	    $next_route_state = $from_info->{bridge} || die 'internal error';
	    $next_physdev_in = $from_info->{fwpr} || die 'internal error';
	    $pkg->{iface_in} = $from_info->{fwbr} || die 'internal error';
	    $pkg->{iface_out} = $from_info->{fwbr} || die 'internal error';
	    $pkg->{physdev_in} = $from_info->{tapdev} || die 'internal error';
	    $pkg->{physdev_out} = $from_info->{fwln} || die 'internal error';
	
	} elsif ($route_state eq 'fwbr-in') {

	    $chain = 'PVEFW-FORWARD';
	    $next_route_state = $target->{tapdev};
	    $pkg->{iface_in} = $target->{fwbr} || die 'internal error';
	    $pkg->{iface_out} = $target->{fwbr} || die 'internal error';
	    $pkg->{physdev_in} = $target->{fwln} || die 'internal error';
	    $pkg->{physdev_out} = $target->{tapdev} || die 'internal error';

	} elsif ($route_state =~ m/^vmbr\d+$/) {
	    
	    die "missing physdev_in - internal error?" if !$physdev_in;

	    if ($target->{type} eq 'host') {

		$chain = 'PVEFW-INPUT';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = 'lo';
		$next_route_state = 'host';

		if ($route_state eq $outside_bridge) {

		} else {

		}

	    } elsif ($target->{type} eq 'outside') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = $outside_bridge;
		$pkg->{physdev_in} = $physdev_in;
		# conditionally set physdev_out (same behavior as kernel)
		if ($route_state eq $outside_bridge) {
		    $pkg->{physdev_out} = $outside_iface || die 'internal error';
		}
		$next_route_state = $outside_iface;

	    } elsif ($target->{type} eq 'ct') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = 'venet0';
		$next_route_state = 'venet-in';

	    } elsif ($target->{type} eq 'vm') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = $target->{bridge};
		$pkg->{physdev_in} = $physdev_in;
		# conditionally set physdev_out (same behavior as kernel)
		if ($route_state eq $target->{bridge}) {
		    $pkg->{physdev_out} = $target->{fwpr} || die 'internal error';
		}
		$next_route_state = 'fwbr-in';

	    } else {
		die "implement me";
	    }

	} else {
	    die "implement me $route_state";
	}

	die "internal error" if !defined($next_route_state);

	if ($chain) {
	    add_trace("IPT check at $route_state (chain $chain)\n");
	    add_trace(Dumper($pkg));
	    my $res = ruleset_simulate_chain($ruleset, $chain, $pkg);
	    return $res if $res ne 'ACCEPT';
	} 

	$route_state = $next_route_state;

	$physdev_in = $next_physdev_in;
    }

    return 'ACCEPT';
}

sub extract_ct_info {
    my ($vmdata, $vmid) = @_;

    my $info = { type => 'ct', vmid => $vmid };

    my $conf = $vmdata->{openvz}->{$vmid} || die "no such CT '$vmid'";
    if ($conf->{ip_address}) {
	$info->{ip_address} = $conf->{ip_address}->{value};
    } else {
	die "implement me";
    }
    return $info;
}

sub extract_vm_info {
    my ($vmdata, $vmid) = @_;

    my $info = { type => 'vm', vmid => $vmid };

    my $conf = $vmdata->{qemu}->{$vmid} || die "no such VM '$vmid'";
    my $net = PVE::QemuServer::parse_net($conf->{net0});
    $info->{macaddr} = $net->{macaddr} || die "unable to get mac address";
    $info->{bridge} = $net->{bridge} || die "unable to get bridge";
    $info->{fwbr} = "fwbr${vmid}i0";
    $info->{tapdev} = "tap${vmid}i0";
    $info->{fwln} = "fwln${vmid}i0";
    $info->{fwpr} = "fwpr${vmid}p0";

    return $info;
}

sub simulate_firewall {
    my ($ruleset, $ipset_ruleset, $vmdata, $test) = @_;

    my $from = delete $test->{from} || die "missing 'from' field";
    my $to = delete $test->{to} || die "missing 'to' field";
    my $action = delete $test->{action} || die "missing 'action'";

    die "from/to needs to be different" if $from eq $to;

    my $pkg = {
	proto => 'tcp',
	sport => '1234',
	dport => '4321',
	source => '10.11.12.13',
	dest => '10.11.12.14',
    };

    while (my ($k,$v) = each %$test) {
	$pkg->{$k} = $v;
    }

    my $from_info = {};

    my $start_state;

    if ($from eq 'host') {
	$from_info->{type} = 'host';
	$start_state = 'host';
    } elsif ($from eq 'outside') {
	$from_info->{type} = 'outside';
	$start_state = 'from-outside';
    } elsif ($from =~ m/^ct(\d+)$/) {
	my $vmid = $1;
	$from_info = extract_ct_info($vmdata, $vmid);
	if ($from_info->{ip_address}) {
	    $pkg->{source} = $from_info->{ip_address};
	    $start_state = 'venet-out';
	} else {
	    die "implement me";
	}
    } elsif ($from =~ m/^vm(\d+)$/) {
	my $vmid = $1;
	$from_info = extract_vm_info($vmdata, $vmid);
	$start_state = 'fwbr-out'; 
	$pkg->{mac_source} = $from_info->{macaddr};
    } else {
	die "implement me";
    }

    my $target;

    if ($to eq 'host') {
	$target->{type} = 'host';
	$target->{iface} = 'host';
    } elsif ($to eq 'outside') {
	$target->{type} = 'outside';
	$target->{iface} = $outside_iface;
    } elsif ($to =~ m/^ct(\d+)$/) {
	my $vmid = $1;
	$target = extract_ct_info($vmdata, $vmid);
	$target->{iface} = 'venet-in';

	if ($target->{ip_address}) {
	    $pkg->{dest} = $target->{ip_address};
	} else {
	    die "implement me";
	}
   } elsif ($to =~ m/^vm(\d+)$/) {
	my $vmid = $1;
	$target = extract_vm_info($vmdata, $vmid);
	$target->{iface} = $target->{tapdev};
    } else {
	die "implement me";
    }

    my $res = route_packet($ruleset, $ipset_ruleset, $pkg, $from_info, $target, $start_state);

    die "test failed ($res != $action)\n" if $action ne $res;

    return undef; 
}

sub run_tests {
    my ($vmdata, $testdir) = @_;

    $vmdata->{testdir} = $testdir;

    my ($ruleset, $ipset_ruleset) = 
	PVE::Firewall::compile(undef, undef, $vmdata);

    my $testfile = "$testdir/tests";
    my $fh = IO::File->new($testfile) ||
	die "unable to open '$testfile' - $!\n";

    while (defined(my $line = <$fh>)) {
	next if $line =~ m/^\s*$/;
	next if $line =~ m/^#.*$/;
	if ($line =~ m/^\{.*\}\s*$/) {
	    my $test = eval $line;
	    die $@ if $@;
	    $trace = '';
	    print Dumper($ruleset) if $debug;
	    eval { simulate_firewall($ruleset, $ipset_ruleset, $vmdata, $test); };
	    if (my $err = $@) {

		print Dumper($ruleset) if !$debug;

		print "$trace\n" if !$debug;

		print "$testfile line $.: $line";

		print "test failed: $err\n";

		exit(-1);
	    }
	} else {
	    die "parse error";
	}
    }

    print "PASS: $testfile\n";

    return undef;
}

my $vmdata = {
    qemu => {
	100 => {
	    net0 => "e1000=0E:0B:38:B8:B3:21,bridge=vmbr0",
	},
	101 => {
	    net0 => "e1000=0E:0B:38:B8:B3:22,bridge=vmbr0",
	},
	# on bridge vmbr1
	110 => {
	    net0 => "e1000=0E:0B:38:B8:B4:21,bridge=vmbr1",
	},
    },
    openvz => {
	200 => {
	    ip_address => { value => '10.0.200.1' },
	},
	201 => {
	    ip_address => { value => '10.0.200.2' },
	},
    },
};

foreach my $dir (<test-*>) {
    next if ! -d $dir;
    run_tests($vmdata, $dir);
}

print "OK - all tests passed\n";

exit(0);
