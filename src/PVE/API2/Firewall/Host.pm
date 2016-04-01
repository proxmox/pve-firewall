package PVE::API2::Firewall::Host;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RPCEnvironment;

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
	    { name => 'log' },
	    ];

	return $result;
    }});

my $option_properties = $PVE::Firewall::host_option_properties;

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
    description => "Get host firewall options.",
    proxyto => 'node',
    permissions => {
	check => ['perm', '/nodes/{node}', [ 'Sys.Audit' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	},
    },
    returns => {
	type => "object",
    	#additionalProperties => 1,
	properties => $option_properties,
    },
    code => sub {
	my ($param) = @_;

	my $hostfw_conf = PVE::Firewall::load_hostfw_conf();

	return PVE::Firewall::copy_opject_with_digest($hostfw_conf->{options});
    }});

__PACKAGE__->register_method({
    name => 'set_options',
    path => 'options',
    method => 'PUT',
    description => "Set Firewall options.",
    protected => 1,
    proxyto => 'node',
    permissions => {
	check => ['perm', '/nodes/{node}', [ 'Sys.Modify' ]],
    },
    parameters => {
    	additionalProperties => 0,
	properties => &$add_option_properties({
	    node => get_standard_option('pve-node'),
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

	my $hostfw_conf = PVE::Firewall::load_hostfw_conf();

	my (undef, $digest) = PVE::Firewall::copy_opject_with_digest($hostfw_conf->{options});
	PVE::Tools::assert_if_modified($digest, $param->{digest});

	if ($param->{delete}) {
	    foreach my $opt (PVE::Tools::split_list($param->{delete})) {
		raise_param_exc({ delete => "no such option '$opt'" }) 
		    if !$option_properties->{$opt};
		delete $hostfw_conf->{options}->{$opt};
	    }
	}

	if (defined($param->{enable})) {
	    $param->{enable} = $param->{enable} ? 1 : 0;
	}

	foreach my $k (keys %$option_properties) {
	    next if !defined($param->{$k});
	    $hostfw_conf->{options}->{$k} = $param->{$k}; 
	}

	PVE::Firewall::save_hostfw_conf($hostfw_conf);

	return undef;
    }});

__PACKAGE__->register_method({
    name => 'log', 
    path => 'log', 
    method => 'GET',
    description => "Read firewall log",
    proxyto => 'node',
    permissions => {
	check => ['perm', '/nodes/{node}', [ 'Sys.Syslog' ]],
    },
    protected => 1,
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    start => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    limit => {
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	},
    },
    returns => {
	type => 'array',
	items => { 
	    type => "object",
	    properties => {
		n => {
		  description=>  "Line number",
		  type=> 'integer',
		},
		t => {
		  description=>  "Line text",
		  type => 'string',
		}
	    }
	}
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $user = $rpcenv->get_user();
	my $node = $param->{node};

	my ($count, $lines) = PVE::Tools::dump_logfile("/var/log/pve-firewall.log", $param->{start}, $param->{limit});

	$rpcenv->set_result_attrib('total', $count);
	    
	return $lines; 
    }});

1;
