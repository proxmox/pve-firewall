package PVE::API2::Firewall::Host;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;
use PVE::API2::Firewall::Rules;

use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::HostRules",  
    path => 'rules',
});

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
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

	my $result = [
	    { name => 'rules' },
	    { name => 'options' },
	    ];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'get_options',
    path => 'options',
    method => 'GET',
    description => "Get host firewall options.",
    proxyto => 'node',
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "object",
	properties => {},
    },
    code => sub {
	my ($param) = @_;

	my $hostfw_conf = PVE::Firewall::load_hostfw_conf();

	return PVE::Firewall::copy_opject_with_digest($hostfw_conf->{options});
    }});

1;
