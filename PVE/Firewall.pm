package PVE::Firewall;

use warnings;
use strict;
use Data::Dumper;
use PVE::Tools;
use PVE::QemuServer;

# we need complete VM configuration of all VMs (openvz/qemu)
# in vmdata

sub compile {
    my ($targetdir, $vmdata) = @_;

    my $netinfo;

    my $zoneinfo = {
	fw => { type => 'firewall' },
    };

    my $register_bridge = sub {
	my ($bridge) = @_;

	my $zone =  'z' . $bridge;

	return $zone if $zoneinfo->{$zone};

	$zoneinfo->{$zone} = {
	    type => 'bridge',
	    bridge => $bridge,
	};
	
	return $zone;
    };

    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	$netinfo->{$vmid} = {};
	my $conf = $vmdata->{qemu}->{$vmid};
	foreach my $opt (keys %$conf) {
	    next if $opt !~ m/^net(\d+)$/;
	    my $netid = $1;
	    my $net = PVE::QemuServer::parse_net($conf->{$opt});
	    next if !$net;
	    die "implement me" if !$net->{bridge};
	    my $bridge = $net->{bridge};
	    my $bridge_zone = &$register_bridge($bridge);
	    if (defined($net->{tag})) {
		$bridge = $bridge .= "v$net->{tag}";
		$bridge_zone = &$register_bridge($bridge);
	    }

	    my $vmzone = $conf->{zone} || "vm$vmid";
	    my $zone = "$bridge_zone$vmzone";
	    $net->{zone} = $zone;
	    $zoneinfo->{$zone}->{type} = 'bport';
	    $zoneinfo->{$zone}->{bridge_zone} = $bridge_zone;
	    $zoneinfo->{$zone}->{ifaces}->{"tap${vmid}i${netid}"} = 1;
	    $netinfo->{$vmid}->{$netid} = $net;
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

    # dump zone file

    my $out;

    my $format = "%-15s %-10s %s\n";
    $out = sprintf($format, '#ZONE', 'TYPE', 'OPTIONS');
    
    foreach my $z (sort keys %$zoneinfo) {
	my $zid = &$lookup_zonename($z);
	if ($zoneinfo->{$z}->{type} eq 'firewall') {
	    $out .= sprintf($format, $zid, $zoneinfo->{$z}->{type}, '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bridge') {
	    $out .= sprintf($format, &$lookup_zonename($z), 'ipv4', '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bport') {
	    my $bridge_zone = $zoneinfo->{$z}->{bridge_zone} || die "internal error";
	    my $bzid = &$lookup_zonename($bridge_zone);
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
	my $zid = &$lookup_zonename($z);
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


}


sub activate {

}


1;
