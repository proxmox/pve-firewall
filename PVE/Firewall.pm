package PVE::Firewall;

use warnings;
use strict;
use Data::Dumper;
use PVE::Tools;
use PVE::QemuServer;


my $rule_format = "%-15s %-15s %-15s %-15s %-15s %-15s\n";

my $generate_input_rule = sub {
    my ($zoneinfo, $rule, $net, $netid) = @_;

    die "not implemented" if $rule->{source} ne 'any';
    die "not implemented" if $rule->{dest} ne 'any';

    my $zone = $net->{zone} || die "internal error";
    my $zid = $zoneinfo->{$zone}->{id} || die "internal error";
    my $tap = $net->{tap} || die "internal error";
    
    return sprintf($rule_format, $rule->{action}, $rule->{source}, "$zid:$tap", 
		   $rule->{proto} || '-', $rule->{dport} || '-', $rule->{sport} || '-');
};

my $generate_output_rule = sub {
    my ($zoneinfo, $rule, $net, $netid) = @_;

    die "not implemented" if $rule->{source} ne 'any';
    die "not implemented" if $rule->{dest} ne 'any';

    my $zone = $net->{zone} || die "internal error";
    my $zid = $zoneinfo->{$zone}->{id} || die "internal error";
    my $tap = $net->{tap} || die "internal error";
    
    return sprintf($rule_format, $rule->{action}, "$zid:$tap", $rule->{dest}, 
		   $rule->{proto} || '-', $rule->{dport} || '-', $rule->{sport} || '-');
};

# we need complete VM configuration of all VMs (openvz/qemu)
# in vmdata

sub compile {
    my ($targetdir, $vmdata, $rules) = @_;

    my $netinfo;

    my $zoneinfo = {
	fw => { type => 'firewall' },
    };

    my $register_bridge;

    $register_bridge = sub {
	my ($bridge, $vlan) = @_;

	my $zone =  'z' . $bridge;

	return $zone if $zoneinfo->{$zone};

	$zoneinfo->{$zone} = {
	    type => 'bridge',
	    bridge => $bridge,
	};

	return &$register_bridge("${bridge}v${vlan}") if defined($vlan);
	
	return $zone;
    };

    my $register_bridge_port = sub {
	my ($bridge, $vlan, $vmzone, $tap) = @_;

	my $bridge_zone = &$register_bridge($bridge, $vlan);
	my $zone = $bridge_zone . $vmzone;

	if (!$zoneinfo->{$zone}) {
	    $zoneinfo->{$zone} = {
		type => 'bport',
		bridge_zone => $bridge_zone,
		ifaces => {},
	    };
	}

	$zoneinfo->{$zone}->{ifaces}->{$tap} = 1;
	
	return $zone;
    };

    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	$netinfo->{$vmid} = {};
	my $conf = $vmdata->{qemu}->{$vmid};
	foreach my $opt (keys %$conf) {
	    next if $opt !~ m/^net(\d+)$/;
	    my $netnum = $1;
	    my $net = PVE::QemuServer::parse_net($conf->{$opt});
	    next if !$net;
	    die "implement me" if !$net->{bridge};

	    my $vmzone = $conf->{zone} || "vm$vmid";
	    $net->{tap} = "tap${vmid}i${netnum}";
	    $net->{zone} = &$register_bridge_port($net->{bridge}, $net->{tag}, $vmzone, $net->{tap});
	    $netinfo->{$vmid}->{$opt} = $net;
	}
    }

    #print Dumper($netinfo);

    # NOTE: zone names have length limit, so we need to
    # translate them into shorter names 

    my $zoneid = 0;
    my $zonemap = { fw => 'fw' };

    my $lookup_zonename = sub {
	my ($zone) = @_;

	return $zonemap->{$zone} if defined($zonemap->{$zone});
	$zonemap->{$zone} = 'z' . $zoneid++;

	return $zonemap->{$zone};
    };

    foreach my $z (sort keys %$zoneinfo) {
	$zoneinfo->{$z}->{id} = &$lookup_zonename($z);
    }

    # dump zone file

    my $out;

    my $format = "%-15s %-10s %s\n";
    $out = sprintf($format, '#ZONE', 'TYPE', 'OPTIONS');
    
    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{id};
	if ($zoneinfo->{$z}->{type} eq 'firewall') {
	    $out .= sprintf($format, $zid, $zoneinfo->{$z}->{type}, '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bridge') {
	    $out .= sprintf($format, $zid, 'ipv4', '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bport') {
	    my $bridge_zone = $zoneinfo->{$z}->{bridge_zone} || die "internal error";
	    my $bzid = $zoneinfo->{$bridge_zone}->{id} || die "internal error";
	    $out .= sprintf($format, "$zid:$bzid", 'bport', '');
	} else {
	    die "internal error";
	}
    }

    $out .= sprintf("#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n");

    PVE::Tools::file_set_contents("$targetdir/zones", $out);

    # dump interfaces

    $format = "%-15s %-20s %-10s %s\n";
    $out = sprintf($format, '#ZONE', 'INTERFACE', 'BROADCAST', 'OPTIONS');

    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{id};
	if ($zoneinfo->{$z}->{type} eq 'firewall') {
	    # do nothing;
	} elsif ($zoneinfo->{$z}->{type} eq 'bridge') {
	    my $bridge = $zoneinfo->{$z}->{bridge} || die "internal error";
	    $out .= sprintf($format, $zid, $bridge, 'detect', 'bridge');

	} elsif ($zoneinfo->{$z}->{type} eq 'bport') {
	    my $ifaces = $zoneinfo->{$z}->{ifaces};
	    foreach my $iface (sort keys %$ifaces) {
		my $bridge_zone = $zoneinfo->{$z}->{bridge_zone} || die "internal error";
		my $bridge = $zoneinfo->{$bridge_zone}->{bridge} || die "internal error";
		my $iftxt = "$bridge:$iface";
		$out .= sprintf($format, $zid, $iftxt, '', '');
	    }
	} else {
	    die "internal error";
	}
    }

    $out .= sprintf("#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n");

    PVE::Tools::file_set_contents("$targetdir/interfaces", $out);

    # dump policy

    $format = "%-15s %-15s %-15s %s\n";
    $out = sprintf($format, '#SOURCE', 'DEST', 'POLICY', 'LOG');
    $out .= sprintf($format, 'all', 'all', 'REJECT', 'info');

    PVE::Tools::file_set_contents("$targetdir/policy", $out);

    # dump rules
    $out = '';

    $out = sprintf($rule_format, '#ACTION', 'SOURCE', 'DEST', 'PROTO', 'DPORT', 'SPORT');
    foreach my $vmid (sort keys %$rules) {
	if (my $inrules = $rules->{$vmid}->{in}) {
	    foreach my $rule (@$inrules) {
		foreach my $netid (keys %{$netinfo->{$vmid}}) {
		    my $net = $netinfo->{$vmid}->{$netid};
		    next if !($rule->{iface} eq 'any' || $rule->{iface} eq $netid);
		    $out .= &$generate_input_rule($zoneinfo, $rule, $net, $netid);
		}
	    }
	}

	if (my $outrules = $rules->{$vmid}->{out}) {
	    foreach my $rule (@$outrules) {
		foreach my $netid (keys %{$netinfo->{$vmid}}) {
		    my $net = $netinfo->{$vmid}->{$netid};
		    next if !($rule->{iface} eq 'any' || $rule->{iface} eq $netid);
		    $out .= &$generate_output_rule($zoneinfo, $rule, $net, $netid);
		}
	    }
	}
    }

    PVE::Tools::file_set_contents("$targetdir/rules", $out);

}


sub activate {

}


1;
