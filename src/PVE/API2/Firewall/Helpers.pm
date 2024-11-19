package PVE::API2::Firewall::Helpers;

use strict;
use warnings;

use PVE::Cluster;
use PVE::Network::SDN::Vnets;
use PVE::RPCEnvironment;

sub get_allowed_vnets {
    my $rpcenv = eval { PVE::RPCEnvironment::get() };

    if ($@) {
	warn "could not initialize RPCEnvironment";
	return {};
    }

    my $authuser = $rpcenv->get_user();

    my $vnets = PVE::Network::SDN::Vnets::config(1);
    my $privs = [ 'SDN.Audit', 'SDN.Allocate' ];

    my $allowed_vnets = [];
    foreach my $vnet (sort keys %{$vnets->{ids}}) {
	my $zone = $vnets->{ids}->{$vnet}->{zone};
	next if !$rpcenv->check_any($authuser, "/sdn/zones/$zone/$vnet", $privs, 1);
	push @$allowed_vnets, $vnet;
    }

    return $allowed_vnets;
}

sub get_allowed_vms {
    my $rpcenv = eval { PVE::RPCEnvironment::get() };

    if ($@) {
	warn "could not initialize RPCEnvironment";
	return {};
    }

    my $authuser = $rpcenv->get_user();

    my $guests = PVE::Cluster::get_vmlist();

    return [
	grep { $rpcenv->check($authuser, "/vms/$_", [ 'VM.Audit' ], 1) } sort keys $guests->{ids}->%*
    ];
}

1;
