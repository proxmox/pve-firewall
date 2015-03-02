package PVE::API2::Firewall::AliasesBase;

use strict;
use warnings;
use PVE::Exception qw(raise raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;

use base qw(PVE::RESTHandler);

my $api_properties = { 
    cidr => {
	description => "Network/IP specification in CIDR format.",
	type => 'string', format => 'IPorCIDR',
    },
    name => get_standard_option('pve-fw-alias'),
    rename => get_standard_option('pve-fw-alias', {
	description => "Rename an existing alias.",
	optional => 1,
    }),
    comment => {
	type => 'string',
	optional => 1,
    },
};

sub load_config {
    my ($class, $param) = @_;

    die "implement this in subclass";

    #return ($fw_conf, $rules);
}

sub save_aliases {
    my ($class, $param, $fw_conf, $aliases) = @_;

    die "implement this in subclass";
}

sub rule_env {
    my ($class, $param) = @_;
    
    die "implement this in subclass";
}

my $additional_param_hash = {};

sub additional_parameters {
    my ($class, $new_value) = @_;

    if (defined($new_value)) {
	$additional_param_hash->{$class} = $new_value;
    }

    # return a copy
    my $copy = {};
    my $org = $additional_param_hash->{$class} || {};
    foreach my $p (keys %$org) { $copy->{$p} = $org->{$p}; }
    return $copy;
}

my $aliases_to_list = sub {
    my ($aliases) = @_;

    my $list = [];
    foreach my $k (sort keys %$aliases) {
	push @$list, $aliases->{$k};
    }
    return $list;
};

sub register_get_aliases {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $class->register_method({
	name => 'get_aliases',
	path => '',
	method => 'GET',
	description => "List aliases",
	permissions => PVE::Firewall::rules_audit_permissions($class->rule_env()),
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => {
	    type => 'array',
	    items => {
		type => "object",
		properties => {
		    name => { type => 'string' },
		    cidr => { type => 'string' },
		    comment => {
			type => 'string',
			optional => 1,
		    },
		    digest => get_standard_option('pve-config-digest', { optional => 0} ),	
		},
	    },
	    links => [ { rel => 'child', href => "{name}" } ],
	},
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $aliases) = $class->load_config($param);

	    my $list = &$aliases_to_list($aliases);

	    return PVE::Firewall::copy_list_with_digest($list);
	}});
}

sub register_create_alias {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{cidr} = $api_properties->{cidr};
    $properties->{comment} = $api_properties->{comment};

    $class->register_method({
	name => 'create_alias',
	path => '',
	method => 'POST',
	description => "Create IP or Network Alias.",
	permissions => PVE::Firewall::rules_modify_permissions($class->rule_env()),
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $aliases) = $class->load_config($param);

	    my $name = lc($param->{name});
	    
	    raise_param_exc({ name => "alias '$param->{name}' already exists" }) 
		if defined($aliases->{$name});
	    
	    my $data = { name => $param->{name}, cidr => $param->{cidr} };
	    $data->{comment} = $param->{comment} if $param->{comment};

	    $aliases->{$name} = $data;

	    $class->save_aliases($param, $fw_conf, $aliases);

	    return undef;
	}});
}

sub register_read_alias {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    
    $class->register_method({
	name => 'read_alias',
	path => '{name}',
	method => 'GET',
	description => "Read alias.",
	permissions => PVE::Firewall::rules_audit_permissions($class->rule_env()),
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "object" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $aliases) = $class->load_config($param);

	    my $name = lc($param->{name});

	    raise_param_exc({ name => "no such alias" })
		if !defined($aliases->{$name});

	    return $aliases->{$name};
	}});
}

sub register_update_alias {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{rename} = $api_properties->{rename};
    $properties->{cidr} = $api_properties->{cidr};
    $properties->{comment} = $api_properties->{comment};
    $properties->{digest} = get_standard_option('pve-config-digest');

    $class->register_method({
	name => 'update_alias',
	path => '{name}',
	method => 'PUT',
	description => "Update IP or Network alias.",
	permissions => PVE::Firewall::rules_modify_permissions($class->rule_env()),
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $aliases) = $class->load_config($param);

	    my $list = &$aliases_to_list($aliases);

	    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($list);

	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    my $name = lc($param->{name});

	    raise_param_exc({ name => "no such alias" }) if !$aliases->{$name};

	    my $data = { name => $param->{name}, cidr => $param->{cidr} };
	    $data->{comment} = $param->{comment} if $param->{comment};

	    $aliases->{$name} = $data;

	    my $rename = lc($param->{rename});

	    if ($rename && ($name ne $rename)) {
		raise_param_exc({ name => "alias '$param->{rename}' already exists" }) 
		    if defined($aliases->{$rename});
		$aliases->{$name}->{name} = $param->{rename};
		$aliases->{$rename} = $aliases->{$name};
		delete $aliases->{$name};
	    }

	    $class->save_aliases($param, $fw_conf, $aliases);

	    return undef;
	}});
}

sub register_delete_alias {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{digest} = get_standard_option('pve-config-digest');

    $class->register_method({
	name => 'remove_alias',
	path => '{name}',
	method => 'DELETE',
	description => "Remove IP or Network alias.",
	permissions => PVE::Firewall::rules_modify_permissions($class->rule_env()),
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $aliases) = $class->load_config($param);

	    my $list = &$aliases_to_list($aliases);
	    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($list);
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    my $name = lc($param->{name});
	    delete $aliases->{$name};

	    $class->save_aliases($param, $fw_conf, $aliases);
	    
	    return undef;
	}});
}

sub register_handlers {
    my ($class) = @_;

    $class->register_get_aliases();
    $class->register_create_alias();
    $class->register_read_alias();
    $class->register_update_alias();
    $class->register_delete_alias();
}

package PVE::API2::Firewall::ClusterAliases;

use strict;
use warnings;

use base qw(PVE::API2::Firewall::AliasesBase);

sub rule_env {
    my ($class, $param) = @_;
    
    return 'cluster';
}

sub load_config {
    my ($class, $param) = @_;

    my $fw_conf = PVE::Firewall::load_clusterfw_conf();
    my $aliases = $fw_conf->{aliases};

    return ($fw_conf, $aliases);
}

sub save_aliases {
    my ($class, $param, $fw_conf, $aliases) = @_;

    $fw_conf->{aliases} = $aliases;
    PVE::Firewall::save_clusterfw_conf($fw_conf);
}

__PACKAGE__->register_handlers();

package PVE::API2::Firewall::VMAliases;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::API2::Firewall::AliasesBase);

sub rule_env {
    my ($class, $param) = @_;
    
    return 'vm';
}

__PACKAGE__->additional_parameters({ 
    node => get_standard_option('pve-node'),
    vmid => get_standard_option('pve-vmid'),				   
});

sub load_config {
    my ($class, $param) = @_;

    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
    my $fw_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, 'vm', $param->{vmid});
    my $aliases = $fw_conf->{aliases};

    return ($fw_conf, $aliases);
}

sub save_aliases {
    my ($class, $param, $fw_conf, $aliases) = @_;

    $fw_conf->{aliases} = $aliases;
    PVE::Firewall::save_vmfw_conf($param->{vmid}, $fw_conf);
}

__PACKAGE__->register_handlers();

package PVE::API2::Firewall::CTAliases;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::API2::Firewall::AliasesBase);

sub rule_env {
    my ($class, $param) = @_;
    
    return 'ct';
}

__PACKAGE__->additional_parameters({ 
    node => get_standard_option('pve-node'),
    vmid => get_standard_option('pve-vmid'),				   
});

sub load_config {
    my ($class, $param) = @_;

    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
    my $fw_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, 'ct', $param->{vmid});
    my $aliases = $fw_conf->{aliases};

    return ($fw_conf, $aliases);
}

sub save_aliases {
    my ($class, $param, $fw_conf, $aliases) = @_;

    $fw_conf->{aliases} = $aliases;
    PVE::Firewall::save_vmfw_conf($param->{vmid}, $fw_conf);
}

__PACKAGE__->register_handlers();

1;
