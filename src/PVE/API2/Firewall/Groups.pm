package PVE::API2::Firewall::Groups;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;
use PVE::API2::Firewall::Rules;

use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'list',
    path => '',
    method => 'GET',
    description => "List security groups.",
    parameters => {
    	additionalProperties => 0,
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => { 
		name => get_standard_option('pve-security-group-name'),
	    },
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $res = [];
	foreach my $group (keys %{$cluster_conf->{groups}}) {
	    push @$res, { name => $group, count => scalar(@{$cluster_conf->{groups}->{$group}}) };
	}

	return $res;
    }});


__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::GroupRules",  
    path => '{group}',
});

1;
