package PVE::FirewallSimulator;

use strict;
use warnings;
use Data::Dumper;
use PVE::Firewall;
use File::Basename;
use Net::IP;

my $mark;
my $trace;
my $debug = 0;

sub debug {
    my $new_value = shift;

    $debug = $new_value if defined($new_value);

    return $debug;
}
    
sub reset_trace {
    $trace = '';
}

sub get_trace {
    return $trace;
}

sub add_trace {
    my ($text) = @_;

    if ($debug) {
	print $text;
    } else {
	$trace .= $text;
    }
}

sub nf_dev_match {
    my ($devre, $dev) = @_;

    $devre =~ s/\+$/\.\*/;
    return  ($dev =~ m/^${devre}$/) ? 1 : 0;
}

sub ipset_match {
    my ($ipsetname, $ipset, $ipaddr) = @_;

    my $ip = Net::IP->new($ipaddr);

    foreach my $entry (@$ipset) {
	next if $entry =~ m/^create/; # simply ignore
	if ($entry =~ m/add \S+ (\S+)$/) {
	    my $test = Net::IP->new($1);
	    if ($test->overlaps($ip)) {
		add_trace("IPSET $ipsetname match $ipaddr\n");
		return 1;
	    }
	} else {
	    die "implement me";
	}
    }

    return 0;
}

sub rule_match {
    my ($ipset_ruleset, $chain, $rule, $pkg) = @_;

    $rule =~ s/^-A $chain // || die "got strange rule: $rule";

    while (length($rule)) {

	if ($rule =~ s/^-m conntrack --ctstate (\S+)\s*//) {
	    my $cstate = $1;

	    return undef if $cstate eq 'INVALID'; # no match
	    return undef if $cstate eq 'RELATED,ESTABLISHED'; # no match
	    
	    next if $cstate =~ m/NEW/;
	    
	    die "please implement cstate test '$cstate'";
	}

	if ($rule =~ s/^-m addrtype --src-type (\S+)\s*//) {
	    my $atype = $1;
	    die "missing srctype" if !$pkg->{srctype};
	    return undef if $atype ne $pkg->{srctype};
	}

	if ($rule =~ s/^-m addrtype --dst-type (\S+)\s*//) {
	    my $atype = $1;
	    die "missing dsttype" if !$pkg->{dsttype};
	    return undef if $atype ne $pkg->{dsttype};
	}

	if ($rule =~ s/^-i (\S+)\s*//) {
	    my $devre = $1;
	    die "missing iface_in" if !$pkg->{iface_in};
	    return undef if !nf_dev_match($devre, $pkg->{iface_in});
	    next;
	}

	if ($rule =~ s/^-o (\S+)\s*//) {
	    my $devre = $1;
	    die "missing iface_out" if !$pkg->{iface_out};
	    return undef if !nf_dev_match($devre, $pkg->{iface_out});
	    next;
	}

	if ($rule =~ s/^-p (tcp|udp)\s*//) {
	    die "missing proto" if !$pkg->{proto};
	    return undef if $pkg->{proto} ne $1; # no match
	    next;
	}

	if ($rule =~ s/^--dport (\d+):(\d+)\s*//) {
	    die "missing dport" if !$pkg->{dport};
	    return undef if ($pkg->{dport} < $1) || ($pkg->{dport} > $2); # no match
	    next;
	}

	if ($rule =~ s/^--dport (\d+)\s*//) {
	    die "missing dport" if !$pkg->{dport};
	    return undef if $pkg->{dport} != $1; # no match
	    next;
	}

	if ($rule =~ s/^-s (\S+)\s*//) {
	    die "missing source" if !$pkg->{source};
	    my $ip = Net::IP->new($1);
	    return undef if !$ip->overlaps(Net::IP->new($pkg->{source})); # no match
	    next;
	}
    
	if ($rule =~ s/^-d (\S+)\s*//) {
	    die "missing destination" if !$pkg->{dest};
	    my $ip = Net::IP->new($1);
	    return undef if !$ip->overlaps(Net::IP->new($pkg->{dest})); # no match
	    next;
	}

	if ($rule =~ s/^-m set --match-set (\S+) src\s*//) {
	    die "missing source" if !$pkg->{source};
	    my $ipset = $ipset_ruleset->{$1};
	    die "no such ip set '$1'" if !$ipset;
	    return undef if !ipset_match($1, $ipset, $pkg->{source});
	    next;
	}

	if ($rule =~ s/^-m set --match-set (\S+) dst\s*//) {
	    die "missing destination" if !$pkg->{dest};
	    my $ipset = $ipset_ruleset->{$1};
	    die "no such ip set '$1'" if !$ipset;
	    return undef if !ipset_match($1, $ipset, $pkg->{dest});
	    next;
	}

	if ($rule =~ s/^-m mac ! --mac-source (\S+)\s*//) {
	    die "missing source mac" if !$pkg->{mac_source};
	    return undef if $pkg->{mac_source} eq $1; # no match
	    next;
	}

	if ($rule =~ s/^-m physdev --physdev-is-bridged --physdev-in (\S+)\s*//) {
	    my $devre = $1;
	    return undef if !$pkg->{physdev_in};
	    return undef if !nf_dev_match($devre, $pkg->{physdev_in});
	    next;
	}

	if ($rule =~ s/^-m physdev --physdev-is-bridged --physdev-out (\S+)\s*//) {
	    my $devre = $1;
	    return undef if !$pkg->{physdev_out};
	    return undef if !nf_dev_match($devre, $pkg->{physdev_out});
	    next;
	}

	if ($rule =~ s/^-m mark --mark (\d+)\s*//) {
	    return undef if !defined($mark) || $mark != $1;
	    next;
	}

	# final actions

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

	if ($rule =~ s/^-j NFLOG --nflog-prefix \"[^\"]+\"$//) {
	    return undef; 
	}

	last;
    }

    die "unable to parse rule: $rule";
}

sub ruleset_simulate_chain {
    my ($ruleset, $ipset_ruleset, $chain, $pkg) = @_;

    add_trace("ENTER chain $chain\n");
    
    my $counter = 0;

    if ($chain eq 'PVEFW-Drop') {
	add_trace("LEAVE chain $chain\n");
	return ('DROP', $counter);
    }
    if ($chain eq 'PVEFW-reject') {
	add_trace("LEAVE chain $chain\n");
	return ('REJECT', $counter);
    }

    if ($chain eq 'PVEFW-tcpflags') {
	add_trace("LEAVE chain $chain\n");
	return (undef, $counter);
    }

    my $rules = $ruleset->{$chain} ||
	die "no such chain '$chain'";

    foreach my $rule (@$rules) {
	$counter++;
	my ($goto, $action) = rule_match($ipset_ruleset, $chain, $rule, $pkg);
	if (!defined($action)) {
	    add_trace("SKIP: $rule\n");
	    next;
	}
	add_trace("MATCH: $rule\n");
	
	if ($action eq 'ACCEPT' || $action eq 'DROP' || $action eq 'REJECT') {
	    add_trace("TERMINATE chain $chain: $action\n");
	    return ($action, $counter);
	} elsif ($action eq 'RETURN') {
	    add_trace("RETURN FROM chain $chain\n");
	    last;
	} else {
	    if ($goto) {
		add_trace("LEAVE chain $chain - goto $action\n");
		return ruleset_simulate_chain($ruleset, $ipset_ruleset, $action, $pkg)
		#$chain = $action;
		#$rules = $ruleset->{$chain} || die "no such chain '$chain'";
	    } else {
		my ($act, $ctr) = ruleset_simulate_chain($ruleset, $ipset_ruleset, $action, $pkg);
		$counter += $ctr;
		return ($act, $counter) if $act;
		add_trace("CONTINUE chain $chain\n");
	    }
	}
    }

    add_trace("LEAVE chain $chain\n");
    if ($chain =~ m/^PVEFW-(INPUT|OUTPUT|FORWARD)$/) {
	return ('ACCEPT', $counter); # default policy
    }

    return (undef, $counter);
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

    my $ipt_invocation_counter = 0;
    my $rule_check_counter = 0;

    while ($route_state ne $target->{iface}) {

	my $chain;
	my $next_route_state;
	my $next_physdev_in;

	$pkg->{iface_in} = $pkg->{iface_out} = undef;
	$pkg->{physdev_in} = $pkg->{physdev_out} = undef;

	if ($route_state eq 'from-bport') {
	    $next_route_state = $from_info->{bridge} || die 'internal error';
	    $next_physdev_in = $from_info->{iface} || die 'internal error';
	} elsif ($route_state eq 'host') {

	    if ($target->{type} eq 'bport') {
		$pkg->{iface_in} = 'lo';
		$pkg->{iface_out} = $target->{bridge} || die 'internal error';
		$chain = 'PVEFW-OUTPUT';
		$next_route_state = $target->{iface} || die 'internal error';
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

	    } elsif ($target->{type} eq 'bport') {
		
		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = 'venet0';
		$pkg->{iface_out} = $target->{bridge} || die 'internal error';
		$next_route_state = $target->{iface} || die 'internal error';

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
	    $pkg->{physdev_in} = $physdev_in;

	    if ($target->{type} eq 'host') {

		$chain = 'PVEFW-INPUT';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = 'lo';
		$next_route_state = 'host';

	    } elsif ($target->{type} eq 'bport') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = $target->{bridge} || die 'internal error';
		# conditionally set physdev_out (same behavior as kernel)
		if ($route_state eq $target->{bridge}) {
		    $pkg->{physdev_out} = $target->{iface} || die 'internal error';
		}
		$next_route_state = $target->{iface};

	    } elsif ($target->{type} eq 'ct') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = 'venet0';
		$next_route_state = 'venet-in';

	    } elsif ($target->{type} eq 'vm') {

		$chain = 'PVEFW-FORWARD';
		$pkg->{iface_in} = $route_state;
		$pkg->{iface_out} = $target->{bridge};
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
	    $ipt_invocation_counter++;
	    my ($res, $ctr) = ruleset_simulate_chain($ruleset, $ipset_ruleset, $chain, $pkg);
	    $rule_check_counter += $ctr;
	    return ($res, $ipt_invocation_counter, $rule_check_counter) if $res ne 'ACCEPT';
	} 

	$route_state = $next_route_state;

	$physdev_in = $next_physdev_in;
    }

    return ('ACCEPT', $ipt_invocation_counter, $rule_check_counter);
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
    my ($ruleset, $ipset_ruleset, $host_ip, $vmdata, $test) = @_;

    my $from = $test->{from} || die "missing 'from' field";
    my $to = $test->{to} || die "missing 'to' field";
    my $action = $test->{action} || die "missing 'action'";
    
    my $testid = $test->{id};
    
    die "from/to needs to be different" if $from eq $to;

    my $pkg = {
	proto => 'tcp',
	sport => undef,
	dport => undef,
	source => undef,
	dest => undef,
	srctype => 'UNICAST',
	dsttype => 'UNICAST',
    };

    while (my ($k,$v) = each %$test) {
	next if $k eq 'from';
	next if $k eq 'to';
	next if $k eq 'action';
	next if $k eq 'id';
	die "unknown attribute '$k'\n" if !exists($pkg->{$k});
	$pkg->{$k} = $v;
    }

    my $from_info = {};

    my $start_state;

    if ($from eq 'host') {
	$from_info->{type} = 'host';
	$start_state = 'host';
	$pkg->{source} = $host_ip if !defined($pkg->{source});
    } elsif ($from =~ m|^(vmbr\d+)/(\S+)$|) {
	$from_info->{type} = 'bport';
	$from_info->{bridge} = $1;
	$from_info->{iface} = $2;
	$start_state = 'from-bport';
    } elsif ($from eq 'outside') {
	$from_info->{type} = 'bport';
	$from_info->{bridge} = 'vmbr0';
	$from_info->{iface} = 'eth0';
	$start_state = 'from-bport';
    } elsif ($from eq 'nfvm') {
	$from_info->{type} = 'bport';
	$from_info->{bridge} = 'vmbr0';
	$from_info->{iface} = 'tapXYZ';
	$start_state = 'from-bport';
    } elsif ($from =~ m/^ct(\d+)$/) {
	my $vmid = $1;
	$from_info = extract_ct_info($vmdata, $vmid);
	if ($from_info->{ip_address}) {
	    $pkg->{source} = $from_info->{ip_address} if !defined($pkg->{source});
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
	die "unable to parse \"from => '$from'\"\n";
    }

    my $target;

    if ($to eq 'host') {
	$target->{type} = 'host';
	$target->{iface} = 'host';
	$pkg->{dest} = $host_ip if !defined($pkg->{dest});
    } elsif ($to =~ m|^(vmbr\d+)/(\S+)$|) {
	$target->{type} = 'bport';
	$target->{bridge} = $1;
	$target->{iface} = $2;
    } elsif ($to eq 'outside') {
	$target->{type} = 'bport';
	$target->{bridge} = 'vmbr0';
	$target->{iface} = 'eth0';
     } elsif ($to eq 'nfvm') {
	$target->{type} = 'bport';
	$target->{bridge} = 'vmbr0';
	$target->{iface} = 'tapXYZ';
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
	die "unable to parse \"to => '$to'\"\n";
    }

    $pkg->{source} = '100.100.1.2' if !defined($pkg->{source});
    $pkg->{dest} = '100.200.3.4' if !defined($pkg->{dest});

    my ($res, $ic, $rc) = route_packet($ruleset, $ipset_ruleset, $pkg, 
				       $from_info, $target, $start_state);

    add_trace("IPT statistics: invocation = $ic, checks = $rc\n");
 
    return $res if $action eq 'QUERY';

    die "test failed ($res != $action)\n" if $action ne $res;

    return undef; 
}

1;
