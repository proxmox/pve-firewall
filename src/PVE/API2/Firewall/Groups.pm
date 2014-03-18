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
	    properties => { 
		name => {
		    description => "Security group name.",
		    type => 'string',
		},
	    },
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $groups_conf = PVE::Firewall::load_security_groups();

	my $res = [];
	foreach my $group (keys %{$groups_conf->{rules}}) {
	    push @$res, { name => $group, count => scalar(@{$groups_conf->{rules}->{$group}}) };
	}

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'get_rules',
    path => '{group}',
    method => 'GET',
    description => "List security groups rules.",
    proxyto => 'node',
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    group => {
		description => "Security group name.",
		type => 'string',
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {},
	},
    },
    code => sub {
	my ($param) = @_;

	my $groups_conf = PVE::Firewall::load_security_groups();

	my $rules = $groups_conf->{rules}->{$param->{group}};
	die "no such security group\n" if !defined($rules);

	my $digest = $groups_conf->{digest};

	my $res = [];

	my $ind = 0;
	foreach my $rule (@$rules) {
	    push @$res, PVE::Firewall::cleanup_fw_rule($rule, $digest, $ind++);
	}

	return $res;
    }});

1;
