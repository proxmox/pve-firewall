package PVE::API2::Firewall::Cluster;

use strict;
use warnings;
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;
use PVE::API2::Firewall::Aliases;
use PVE::API2::Firewall::Rules;
use PVE::API2::Firewall::Groups;
use PVE::API2::Firewall::Helpers;
use PVE::API2::Firewall::IPSet;

#fixme: locking?


use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::Groups",
    path => 'groups',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::ClusterRules",
    path => 'rules',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::ClusterIPSetList",
    path => 'ipset',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::ClusterAliases",
    path => 'aliases',
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
	    { name => 'aliases' },
	    { name => 'rules' },
	    { name => 'options' },
	    { name => 'groups' },
	    { name => 'ipset' },
	    { name => 'macros' },
	    { name => 'refs' },
	    ];

	return $result;
    }});

my $option_properties = $PVE::Firewall::cluster_option_properties;

my $add_option_properties = sub {
    my ($properties) = @_;

    foreach my $k (keys %$option_properties) {
	$properties->{$k} = $option_properties->{$k};
    }

    return $properties;
};


__PACKAGE__->register_method({
    name => 'get_options',
    path => 'options',
    method => 'GET',
    description => "Get Firewall options.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
    	additionalProperties => 0,
    },
    returns => {
	type => "object",
    	#additionalProperties => 1,
	properties => $option_properties,
    },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	return PVE::Firewall::copy_opject_with_digest($cluster_conf->{options});
    }});


__PACKAGE__->register_method({
    name => 'set_options',
    path => 'options',
    method => 'PUT',
    description => "Set Firewall options.",
    protected => 1,
    permissions => {
	check => ['perm', '/', [ 'Sys.Modify' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => &$add_option_properties({
	    delete => {
		type => 'string', format => 'pve-configid-list',
		description => "A list of settings you want to delete.",
		optional => 1,
	    },
	    digest => get_standard_option('pve-config-digest'),
	}),
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	PVE::Firewall::lock_clusterfw_conf(10, sub {
	    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	    my (undef, $digest) = PVE::Firewall::copy_opject_with_digest($cluster_conf->{options});
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    if ($param->{delete}) {
		foreach my $opt (PVE::Tools::split_list($param->{delete})) {
		    raise_param_exc({ delete => "no such option '$opt'" })
			if !$option_properties->{$opt};
		    delete $cluster_conf->{options}->{$opt};
		}
	    }

	    if (defined($param->{enable}) && ($param->{enable} > 1)) {
		$param->{enable} = time();
	    }

	    foreach my $k (keys %$option_properties) {
		next if !defined($param->{$k});
		$cluster_conf->{options}->{$k} = $param->{$k};
	    }

	    PVE::Firewall::save_clusterfw_conf($cluster_conf);
	});

	# instant firewall update when using double (anti-lockout) API call
	# -> not waiting for a firewall update at the first (timestamp enable) set
	if (defined($param->{enable}) && ($param->{enable} > 1)) {
	    PVE::Firewall::update();
	}

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'get_macros',
    path => 'macros',
    method => 'GET',
    description => "List available macros",
    permissions => { user => 'all' },
    parameters => {
    	additionalProperties => 0,
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		macro => {
		    description => "Macro name.",
		    type => 'string',
		},
		descr => {
		    description => "More verbose description (if available).",
		    type => 'string',
		}
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	my ($macros, $descr) = PVE::Firewall::get_macros();

	foreach my $macro (keys %$macros) {
	    push @$res, { macro => $macro, descr => $descr->{$macro} || $macro };
	}

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'refs',
    path => 'refs',
    method => 'GET',
    description => "Lists possible IPSet/Alias reference which are allowed in source/dest properties.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    type => {
		description => "Only list references of specified type.",
		type => 'string',
		enum => ['alias', 'ipset'],
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		type => {
		    type => 'string',
		    enum => ['alias', 'ipset'],
		},
		name => {
		    type => 'string',
		},
		ref => {
		    type => 'string',
		},
		scope => {
		    type => 'string',
		},
		comment => {
		    type => 'string',
		    optional => 1,
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $conf = PVE::Firewall::load_clusterfw_conf();

	# we are explicitly loading the SDN config here with the scope of the current
	# API user, so we only return the IPSets that the user can actually use
	my $allowed_vms = PVE::API2::Firewall::Helpers::get_allowed_vms();
	my $allowed_vnets = PVE::API2::Firewall::Helpers::get_allowed_vnets();
	my $sdn_conf = PVE::Firewall::load_sdn_conf($allowed_vms, $allowed_vnets);

	my $cluster_refs = PVE::Firewall::Helpers::collect_refs($conf, $param->{type}, "dc");
	my $sdn_refs = PVE::Firewall::Helpers::collect_refs($sdn_conf, $param->{type}, "sdn");

	return [@$sdn_refs, @$cluster_refs];
    }});

1;
