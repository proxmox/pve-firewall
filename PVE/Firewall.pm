package PVE::Firewall;

use warnings;
use strict;
use Data::Dumper;
use PVE::Tools;
use PVE::QemuServer;

my $macros;
sub get_shorewall_macros {

    return $macros if $macros;

    foreach my $path (</usr/share/shorewall/macro.*>) {
	if ($path =~ m|/macro\.(\S+)$|) {
	    $macros->{$1} = 1;
	}
    }
    return $macros;
}


my $rule_format = "%-15s %-30s %-30s %-15s %-15s %-15s\n";

my $generate_input_rule = sub {
    my ($zoneinfo, $rule, $net, $netid) = @_;

    my $zone = $net->{zone} || die "internal error";
    my $zid = $zoneinfo->{$zone}->{zoneref} || die "internal error";
    my $tap = $net->{tap} || die "internal error";

    my $dest = "$zid:$tap";

    if ($rule->{dest}) {
	$dest .= ":$rule->{dest}";
    }

    my $action = $rule->{service} ? 
	"$rule->{service}($rule->{action})" : $rule->{action};

    my $source;

    if ($zoneinfo->{$zone}->{type} eq 'bport') {
	my $bridge_zone = $zoneinfo->{$zone}->{bridge_zone} || die "internal error";
	my $bridge_ext_zone = $zoneinfo->{$bridge_zone}->{bridge_ext_zone} || die "internal error";
	my $zoneref = $zoneinfo->{$bridge_ext_zone}->{zoneref} || die "internal error";
	if (!$rule->{source}) {
	    $source = "${zoneref}";
	} else {
	    $source = "${zoneref}:$rule->{source}";
	}
    } else {
	$source = "any:$rule->{source}";
    }

    return sprintf($rule_format, $action, $source, $dest, $rule->{proto} || '-', 
		   $rule->{dport} || '-', $rule->{sport} || '-');
};

my $generate_output_rule = sub {
    my ($zoneinfo, $rule, $net, $netid) = @_;

    my $zone = $net->{zone} || die "internal error";
    my $zid = $zoneinfo->{$zone}->{zoneref} || die "internal error";
    my $tap = $net->{tap} || die "internal error";

    my $action = $rule->{service} ? 
	"$rule->{service}($rule->{action})" : $rule->{action};
    
    my $dest;

    if (!$rule->{dest}) {
	$dest = 'any';
    } else {
	$dest = "any:$rule->{dest}";
    }

    return sprintf($rule_format, $action, "$zid:$tap", $dest, 
		   $rule->{proto} || '-', $rule->{dport} || '-', $rule->{sport} || '-');
};

# we need complete VM configuration of all VMs (openvz/qemu)
# in vmdata

sub compile {
    my ($targetdir, $vmdata, $rules) = @_;

    # remove existing data ?
    foreach my $file (qw(params zones rules interfaces  maclist  policy)) {
	unlink "$targetdir/$file";
    }

    my $netinfo;

    my $zoneinfo = {
	fw => { type => 'firewall' },
    };

    my $maclist = {};

    my $register_bridge;

    $register_bridge = sub {
	my ($bridge, $vlan) = @_;

	my $zone =  'z' . $bridge;

	return $zone if $zoneinfo->{$zone};

	my $ext_zone = "z${bridge}ext";

	$zoneinfo->{$zone} = {
	    type => 'bridge',
	    bridge => $bridge,
	    bridge_ext_zone => $ext_zone,
	};

	# physical input devices
	my $dir = "/sys/class/net/$bridge/brif";
	my $physical = {};
	PVE::Tools::dir_glob_foreach($dir, '((eth|bond).+)', sub {
	    my ($slave) = @_;
	    $physical->{$slave} = 1;
	});

	$zoneinfo->{$ext_zone} = {
	    type => 'bport',
	    bridge_zone => $zone,
	    ifaces => $physical,
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
	    $maclist->{$net->{tap}} = $net->{macaddr} || die "internal error";
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
	$zoneinfo->{$z}->{zonevar} = uc($z);
 	$zoneinfo->{$z}->{zoneref} = '$' . $zoneinfo->{$z}->{zonevar};
    }

    my $out;

    # dump params file
    $out = "# PVE zones\n";
    foreach my $z (sort keys %$zoneinfo) {
	$out .= "$zoneinfo->{$z}->{zonevar}=$zoneinfo->{$z}->{id}\n";
    }
    PVE::Tools::file_set_contents("$targetdir/params", $out);

    # dump zone file

    my $format = "%-30s %-10s %-15s\n";
    $out = sprintf($format, '#ZONE', 'TYPE', 'OPTIONS');
    
    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{zoneref};
	if ($zoneinfo->{$z}->{type} eq 'firewall') {
	    $out .= sprintf($format, $zid, $zoneinfo->{$z}->{type}, '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bridge') {
	    $out .= sprintf($format, $zid, 'ipv4', '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bport') {
	    my $bridge_zone = $zoneinfo->{$z}->{bridge_zone} || die "internal error";
	    my $bzid = $zoneinfo->{$bridge_zone}->{zoneref} || die "internal error";
	    $out .= sprintf($format, "$zid:$bzid", 'bport', '');
	} else {
	    die "internal error";
	}
    }

    $out .= sprintf("#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n");

    PVE::Tools::file_set_contents("$targetdir/zones", $out);

    # dump interfaces

    $format = "%-25s %-20s %-10s %-15s\n";
    $out = sprintf($format, '#ZONE', 'INTERFACE', 'BROADCAST', 'OPTIONS');

    my $maclist_format = "%-15s %-15s %-15s\n";
    my $macs = sprintf($maclist_format, '#DISPOSITION', 'INTERFACE', 'MACZONE');

    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{zoneref};
	if ($zoneinfo->{$z}->{type} eq 'firewall') {
	    # do nothing;
	} elsif ($zoneinfo->{$z}->{type} eq 'bridge') {
	    my $bridge = $zoneinfo->{$z}->{bridge} || die "internal error";
	    $out .= sprintf($format, $zid, $bridge, 'detect', 'bridge,optional');
	} elsif ($zoneinfo->{$z}->{type} eq 'bport') {
	    my $ifaces = $zoneinfo->{$z}->{ifaces};
	    foreach my $iface (sort keys %$ifaces) {
		my $bridge_zone = $zoneinfo->{$z}->{bridge_zone} || die "internal error";
		my $bridge = $zoneinfo->{$bridge_zone}->{bridge} || die "internal error";
		my $iftxt = "$bridge:$iface";

		if ($maclist->{$iface}) {
		    $out .= sprintf($format, $zid, $iftxt, '-', 'maclist');
		    $macs .= sprintf($maclist_format, 'ACCEPT', $iface, $maclist->{$iface});
		} else {
		    $out .= sprintf($format, $zid, $iftxt, '-', '');
		}
	    }
	} else {
	    die "internal error";
	}
    }

    $out .= sprintf("#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n");

    PVE::Tools::file_set_contents("$targetdir/interfaces", $out);

    # dump maclist
    PVE::Tools::file_set_contents("$targetdir/maclist", $macs);

    # dump policy

    $format = "%-15s %-15s %-15s %s\n";
    $out = sprintf($format, '#SOURCE', 'DEST', 'POLICY', 'LOG');
    $out .= sprintf($format, 'fw', 'all', 'ACCEPT', '');

    # we need to disable intra-zone traffic on bridges. Else traffic
    # from untracked interfaces simply pass the firewall
    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{zoneref};
	if ($zoneinfo->{$z}->{type} eq 'bridge') {
	    $out .= sprintf($format, $zid, $zid, 'REJECT', 'info');
	}
    }
    $out .= sprintf($format, 'all', 'all', 'REJECT', 'info');

    PVE::Tools::file_set_contents("$targetdir/policy", $out);

    # dump rules
    $out = '';

    $out = sprintf($rule_format, '#ACTION', 'SOURCE', 'DEST', 'PROTO', 'DPORT', 'SPORT');
    foreach my $vmid (sort keys %$rules) {
	my $inrules = $rules->{$vmid}->{in};
	my $outrules = $rules->{$vmid}->{out};

	if (scalar(@$inrules)) {
	    $out .= "# IN to VM $vmid\n";
	    foreach my $rule (@$inrules) {
		foreach my $netid (keys %{$netinfo->{$vmid}}) {
		    my $net = $netinfo->{$vmid}->{$netid};
		    next if !($rule->{iface} eq 'any' || $rule->{iface} eq $netid);
		    $out .= &$generate_input_rule($zoneinfo, $rule, $net, $netid);
		}
	    }
	}

	if (scalar(@$outrules)) {
	    $out .= "# OUT from VM $vmid\n";
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
