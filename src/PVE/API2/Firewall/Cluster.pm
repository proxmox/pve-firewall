package PVE::API2::Firewall::Cluster;

use strict;
use warnings;
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;
use PVE::API2::Firewall::Groups;

#fixme: locking?

use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::Groups",  
    path => 'groups',
});

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    permissions => { user => 'all' },
    description => "Directory index.",
    parameters => {
    	additionalProperties => 0,
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
	    { name => 'groups' },
	    { name => 'netgroups' },
	    ];

	return $result;
    }});

__PACKAGE__->register_method({
    name => 'get_options',
    path => 'options',
    method => 'GET',
    description => "Get Firewall options.",
    parameters => {
    	additionalProperties => 0,
    },
    returns => {
	type => "object",
    	#additionalProperties => 1,
	properties => {
	    enable => {
		type => 'boolean',
		optional => 1,
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $options = $cluster_conf->{options};

	return $options;
    }});

my $option_properties = {
    enable => {
	type => 'boolean',
	optional => 1,
    },
};

my $add_option_properties = sub {
    my ($properties) = @_;

    foreach my $k (keys %$option_properties) {
	$properties->{$k} = $option_properties->{$k};
    }
    
    return $properties;
};

__PACKAGE__->register_method({
    name => 'set_options',
    path => 'options',
    method => 'PUT',
    description => "Set Firewall options.",
    parameters => {
    	additionalProperties => 0,
	properties => &$add_option_properties({
	    delete => {
		type => 'string', format => 'pve-configid-list',
		description => "A list of settings you want to delete.",
		optional => 1,
	    },
	}),
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	if ($param->{delete}) {
	    foreach my $opt (PVE::Tools::split_list($param->{delete})) {
		raise_param_exc({ delete => "no such option '$opt'" }) 
		    if !$option_properties->{$opt};
		delete $cluster_conf->{options}->{$opt};
	    }
	}

	if (defined($param->{enable})) {
	    $cluster_conf->{options}->{enable} = $param->{enable} ? 1 : 0;
	}


	PVE::Firewall::save_clusterfw_conf($cluster_conf);

	return undef;
    }});
