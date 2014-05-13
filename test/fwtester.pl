#!/usr/bin/perl

use lib '../src';
use strict;
use warnings;
use Data::Dumper;
use PVE::Firewall;

my $mark;
my $trace;

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

    $trace .= "ENTER chain $chain\n";
    
    if ($chain eq 'PVEFW-Drop') {
	$trace .= "LEAVE chain $chain\n";
	return 'DROP';
    }
    if ($chain eq 'PVEFW-reject') {
	$trace .= "LEAVE chain $chain\n";
	return 'REJECT';
    }

    if ($chain eq 'PVEFW-tcpflags') {
	$trace .= "LEAVE chain $chain\n";
	return undef;
    }

    my $rules = $ruleset->{$chain} ||
	die "no such chain '$chain'";

    foreach my $rule (@$rules) {
	my ($goto, $action) = rule_match($chain, $rule, $pkg);
	if (!defined($action)) {
	    $trace .= "SKIP: $rule\n";
	    next;
	}
	$trace .= "MATCH: $rule\n";
	
	if ($action eq 'ACCEPT' || $action eq 'DROP' || $action eq 'REJECT') {
	    $trace .= "TERMINATE chain $chain: $action\n";
	    return $action;
	} elsif ($action eq 'RETURN') {
	    $trace .= "RETURN FROM chain $chain\n";
	    last;
	} else {
	    if ($goto) {
		$trace .= "LEAVE chain $chain - goto $action\n";
		return ruleset_simulate_chain($ruleset, $action, $pkg)
		#$chain = $action;
		#$rules = $ruleset->{$chain} || die "no such chain '$chain'";
	    } else {
		if ($action = ruleset_simulate_chain($ruleset, $action, $pkg)) {
		    return $action;
		}
		$trace .= "CONTINUE chain $chain\n";
	    }
	}
    }

    $trace .= "LEAVE chain $chain\n";
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


sub simulate_firewall {
    my ($ruleset, $ipset_ruleset, $vmdata, $test) = @_;

    my $from = delete $test->{from} || die "missing 'from' field";
    my $to = delete $test->{to} || die "missing 'to' field";
    my $action = delete $test->{action} || die "missing 'action'";

    die "from/to needs to be different" if $from eq $to;

    my $pkg = {
	iface_in => 'lo',
	iface_out => 'lo',
	proto => 'tcp',
	sport => '1234',
	dport => '4321',
	source => '10.11.12.13',
	dest => '10.11.12.14',
    };

    while (my ($k,$v) = each %$test) {
	$pkg->{$k} = $v;
    }

    my $pre_test;

    if ($from eq 'host') {
	$pre_test = ['PVEFW-OUTPUT', $pkg];
    } elsif ($from =~ m/^ct(\d+)$/) {
	my $vmid = $1;
	my $conf = $vmdata->{openvz}->{$vmid} || die "no such CT '$vmid'";
	if ($conf->{ip_address}) {
	    $pkg->{source} = $conf->{ip_address}->{value};
	    $pkg->{iface_in} = 'venet0';
	} else {
	    die "implement me";
	}
	$pre_test = ['PVEFW-FORWARD', $pkg];
    } elsif ($from =~ m/^vm(\d+)$/) {
	my $vmid = $1;
	my $conf = $vmdata->{qemu}->{$vmid} || die "no such VM '$vmid'";
	my $net = PVE::QemuServer::parse_net($conf->{net0});
	my $macaddr = $net->{macaddr} || die "unable to get mac address";
	$pkg->{iface_in} = $net->{bridge} || die "unable to get bridge";
	$pkg->{mac_source} = $macaddr;
	my $brpkg = copy_packet($pkg);
	$brpkg->{physdev_in} = "tap${vmid}i0";
	$brpkg->{physdev_out} = "link${vmid}i0";
	$brpkg->{iface_in} = $brpkg->{iface_out} = "fwbr${vmid}i0";
	$pre_test = ['PVEFW-FORWARD', $brpkg];
    } else {
	die "implement me";
    }

    my $post_test;
    if ($to eq 'host') {
	$post_test = ['PVEFW-INPUT', $pkg];
    } elsif ($to =~ m/^ct(\d+)$/) {
	my $vmid = $1;
	my $conf = $vmdata->{openvz}->{$vmid} || die "no such CT '$vmid'";
	if ($conf->{ip_address}) {
	    $pkg->{dest} = $conf->{ip_address}->{value};
	    $pkg->{iface_out} = 'venet0';
	} else {
	    die "implement me";
	}
	$post_test = ['PVEFW-FORWARD', $pkg];
   } elsif ($to =~ m/^vm(\d+)$/) {
	my $vmid = $1;
	my $conf = $vmdata->{qemu}->{$vmid} || die "no such VM '$vmid'";
	my $net = PVE::QemuServer::parse_net($conf->{net0});
	$pkg->{iface_out} = $net->{bridge} || die "unable to get bridge";
	my $brpkg = copy_packet($pkg);
	$brpkg->{physdev_out} = "tap${vmid}i0";
	$brpkg->{physdev_in} = "link${vmid}i0";
	$brpkg->{iface_in} = $brpkg->{iface_out} = "fwbr${vmid}i0";
	$post_test = ['PVEFW-FORWARD', $brpkg];
    } else {
	die "implement me";
    }

    my $res = 'UNKNOWN';
    if ($pre_test) {
	my ($chain, $testpkg) = @$pre_test;
	$trace .= "PRE TEST $chain: " . Dumper($testpkg);
	$res = ruleset_simulate_chain($ruleset, $chain, $testpkg);
	if ($res ne 'ACCEPT') {
	    die "test failed ($res != $action)\n" if $action ne $res;
	    return undef; # sucess
	}
    }
   
    if ($post_test) {
	my ($chain, $testpkg) = @$post_test;
	$trace .= "POST TEST $chain: " . Dumper($testpkg);
	$res = ruleset_simulate_chain($ruleset, $chain, $testpkg);
	if ($res ne 'ACCEPT') {
	    die "test failed ($res != $action)\n" if $action ne $res;
	    return undef; # sucess
	}
    }

    die "test failed ($res != $action)\n" if $action ne $res; # fixme: remove

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
	    eval { simulate_firewall($ruleset, $ipset_ruleset, $vmdata, $test); };
	    if (my $err = $@) {

		print Dumper($ruleset);

		print "$trace\n";

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
	    net0 => "e1000=0E:0B:38:B8:B3:21,bridge=vmbr0,firewall=0",
	},
    },
    openvz => {
	200 => {
	    ip_address => { value => '10.0.200.1' },
	},
    },
};

foreach my $dir (<test-*>) {
    next if ! -d $dir;
    run_tests($vmdata, $dir);
}

print "OK - all tests passed\n";

exit(0);
