package PVE::API2::Firewall::Groups;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;


use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'list',
    path => '',
    method => 'GET',
    description => "List security groups.",
    proxyto => 'node',
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $groups_conf = PVE::Firewall::load_security_groups();

	my $res = [];
	foreach my $group (keys %{$groups_conf->{rules}}) {
	    push @$res, { name => $group };
	}

	return $res;
    }});

1;
