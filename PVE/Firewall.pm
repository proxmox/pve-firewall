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

    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	$netinfo->{$vmid} = {};
	my $conf = $vmdata->{qemu}->{$vmid};
	foreach my $opt (keys %$conf) {
	    next if $opt !~ m/^net(\d+)$/;
	    my $net = PVE::QemuServer::parse_net($conf->{$opt});
	    next if !$net;
	    $netinfo->{$vmid} = $net;
	}
    }

    print Dumper($netinfo);

}

sub activate {

}


1;
