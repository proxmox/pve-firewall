package PVE::Firewall;

use warnings;
use strict;
use Data::Dumper;

use PVE::QemuServer;

# we need complete VM configuration of all VMs (openvz/qemu)
# in vmdata

sub compile {
    my ($vmdata) = @_;

    my $netinfo;

    my $bridges = {};
    my $zoneinfo = {
	fw => { type => 'firewall' },
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
	    $bridges->{$bridge} = 1;
	    $zoneinfo->{$bridge}->{type} = 'ipv4';
	    $zoneinfo->{$bridge}->{ifaces}->{$bridge} = 1;
	    if (defined($net->{tag})) {
		$bridge = $bridge .= "v$net->{tag}";
		$bridges->{$bridge} = 1;
		$zoneinfo->{$bridge}->{type} = 'ipv4';
		$zoneinfo->{$bridge}->{ifaces}->{$bridge} = 1;
	    }

	    my $zone = $bridge . ($conf->{zone} || "vm$vmid");
	    $net->{zone} = $zone;
	    $zoneinfo->{$zone}->{type} = 'bport';
	    $zoneinfo->{$zone}->{bridge} = $bridge;
	    $zoneinfo->{$zone}->{ifaces}->{"tap${vmid}i${netid}"} = 1;
	    $netinfo->{$vmid}->{$netid} = $net;
	}
    }

    #print Dumper($netinfo);

    # TODO: zone names have length limit, so we need to
    # translate them into shorter names 

    # dump zone file

    print "DUMP: zones\n";
    my $format = "%-15s %-10s %s\n";
    printf($format, '#ZONE', 'TYPE', 'OPTIONS');

    foreach my $z (sort keys %$zoneinfo) {
	printf($format, $z, $zoneinfo->{$z}->{type}, '');
    }

    print "#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n";

    print "\n";
    print "DUMP: interfaces\n";

    $format = "%-15s %-20s %-10s %s\n";
    printf($format, '#ZONE', 'INTERFACE', 'BROADCAST', 'OPTIONS');
    foreach my $z (sort keys %$zoneinfo) {
	my $ifaces = $zoneinfo->{$z}->{ifaces};
	foreach my $iface (sort keys %$ifaces) {
	    my $broadcast =  $zoneinfo->{$z}->{type} eq 'ipv4' ? 'detect' : '';
	    my $options =  $bridges->{$iface} ? 'bridge' : '';
	    my $bridge = $zoneinfo->{$z}->{bridge} || '';
	    my $iftxt = $zoneinfo->{$z}->{bridge} ? "$zoneinfo->{$z}->{bridge}:$iface" : $iface;
	    printf($format, $z, $iftxt, $broadcast, $options);
	}
    }

    print "#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n";

    print "\n";


}


sub activate {

}


1;
