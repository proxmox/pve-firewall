package PVE::API2::Firewall::VMBase;

use strict;
use warnings;

use PVE::Exception qw(raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;
use PVE::Firewall;
use PVE::API2::Firewall::Rules;
use PVE::API2::Firewall::Aliases;

use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

my $option_properties = $PVE::Firewall::vm_option_properties;

my $add_option_properties = sub {
    my ($properties) = @_;

    foreach my $k (keys %$option_properties) {
	$properties->{$k} = $option_properties->{$k};
    }
    
    return $properties;
};

sub register_handlers {
    my ($class, $rule_env) = @_;

    $class->register_method({
	name => 'index',
	path => '',
	method => 'GET',
	permissions => { user => 'all' },
	description => "Directory index.",
	parameters => {
	    additionalProperties => 0,
	    properties => {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
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
		{ name => 'aliases' },
		{ name => 'ipset' },
		{ name => 'refs' },
		{ name => 'options' },
		];

	    return $result;
	}});


    $class->register_method({
	name => 'get_options',
	path => 'options',
	method => 'GET',
	description => "Get VM firewall options.",
	proxyto => 'node',
	permissions => {
	    check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
	},
	parameters => {
	    additionalProperties => 0,
	    properties => {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
	    },
	},
	returns => {
	    type => "object",
	    #additionalProperties => 1,
	    properties => $option_properties,
	},
	code => sub {
	    my ($param) = @_;

	    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
	    my $vmfw_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, $rule_env, $param->{vmid});

	    return PVE::Firewall::copy_opject_with_digest($vmfw_conf->{options});
	}});

    $class->register_method({
	name => 'set_options',
	path => 'options',
	method => 'PUT',
	description => "Set Firewall options.",
	protected => 1,
	proxyto => 'node',
	permissions => {
	    check => ['perm', '/vms/{vmid}', [ 'VM.Config.Network' ]],
	},
	parameters => {
	    additionalProperties => 0,
	    properties => &$add_option_properties({
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
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


	    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
	    my $vmfw_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, $rule_env, $param->{vmid});

	    my (undef, $digest) = PVE::Firewall::copy_opject_with_digest($vmfw_conf->{options});
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    if ($param->{delete}) {
		foreach my $opt (PVE::Tools::split_list($param->{delete})) {
		    raise_param_exc({ delete => "no such option '$opt'" }) 
			if !$option_properties->{$opt};
		    delete $vmfw_conf->{options}->{$opt};
		}
	    }

	    if (defined($param->{enable})) {
		$param->{enable} = $param->{enable} ? 1 : 0;
	    }

	    foreach my $k (keys %$option_properties) {
		next if !defined($param->{$k});
		$vmfw_conf->{options}->{$k} = $param->{$k}; 
	    }

	    PVE::Firewall::save_vmfw_conf($param->{vmid}, $vmfw_conf);
	    
	    return undef;
	}});

    $class->register_method({
	name => 'log', 
	path => 'log', 
	method => 'GET',
	description => "Read firewall log",
	proxyto => 'node',
	permissions => {
	    check => ['perm', '/vms/{vmid}', [ 'VM.Console' ]],
	},
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
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
	    my $vmid = $param->{vmid};

	    my ($count, $lines) = PVE::Tools::dump_logfile("/var/log/pve-firewall.log", 
							   $param->{start}, $param->{limit},
							   "^$vmid ");
	    
	    $rpcenv->set_result_attrib('total', $count);
	    
	    return $lines; 
	}});


    $class->register_method({
	name => 'refs',
	path => 'refs',
	method => 'GET',
	description => "Lists possible IPSet/Alias reference which are allowed in source/dest properties.",
	permissions => {
	    check => ['perm', '/vms/{vmid}', [ 'VM.Audit' ]],
	},
	parameters => {
	    additionalProperties => 0,
	    properties => {
		node => get_standard_option('pve-node'),
		vmid => get_standard_option('pve-vmid'),
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
		    comment => { 
			type => 'string',
			optional => 1,
		    },
		},
	    },
	},
	code => sub {
	    my ($param) = @_;
	    
	    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
	    my $fw_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, $rule_env, $param->{vmid});

	    my $ipsets = {};
	    my $aliases = {};

	    foreach my $conf (($cluster_conf, $fw_conf)) {
		next if !$conf;
		if (!$param->{type} || $param->{type} eq 'ipset') {
		    foreach my $name (keys %{$conf->{ipset}}) {
			my $data = { 
			    type => 'ipset',
			    name => $name,
			    ref => "+$name",
			};
			if (my $comment = $conf->{ipset_comments}->{$name}) {
			    $data->{comment} = $comment;
			}
			$ipsets->{$name} = $data;
		    }
		}

		if (!$param->{type} || $param->{type} eq 'alias') {
		    foreach my $name (keys %{$conf->{aliases}}) {
			my $e = $conf->{aliases}->{$name};
			my $data = { 
			    type => 'alias',
			    name => $name,
			    ref => $name,
			};
			$data->{comment} = $e->{comment} if $e->{comment};
			$aliases->{$name} = $data;
		    }
		}
	    }

	    my $res = [];
	    foreach my $e (values %$ipsets) { push @$res, $e; };
	    foreach my $e (values %$aliases) { push @$res, $e; };
	    
	    return $res; 
	}});
}

package PVE::API2::Firewall::VM;

use strict;
use warnings;

use base qw(PVE::API2::Firewall::VMBase);

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::VMRules",  
    path => 'rules',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::VMAliases",  
    path => 'aliases',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::VMIPSetList",  
    path => 'ipset',
});

__PACKAGE__->register_handlers('vm');

package PVE::API2::Firewall::CT;

use strict;
use warnings;

use base qw(PVE::API2::Firewall::VMBase);

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::CTRules",  
    path => 'rules',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::CTAliases",  
    path => 'aliases',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::CTIPSetList",  
    path => 'ipset',
});

__PACKAGE__->register_handlers('vm');

1;
