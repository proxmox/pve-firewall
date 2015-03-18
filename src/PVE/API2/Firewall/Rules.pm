package PVE::API2::Firewall::RulesBase;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise raise_param_exc);

use PVE::Firewall;

use base qw(PVE::RESTHandler);

my $api_properties = { 
    pos => {
	description => "Rule position.",
	type => 'integer',
	minimum => 0,
    },
};

sub load_config {
    my ($class, $param) = @_;

    die "implement this in subclass";

    #return ($cluster_conf, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    die "implement this in subclass";
}

my $additional_param_hash = {};

sub rule_env {
    my ($class, $param) = @_;
    
    die "implement this in subclass";
}

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

sub register_get_rules {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    my $rule_env = $class->rule_env();

    $class->register_method({
	name => 'get_rules',
	path => '',
	method => 'GET',
	description => "List rules.",
	permissions => PVE::Firewall::rules_audit_permissions($rule_env),
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	proxyto => $rule_env eq 'host' ? 'node' : undef,
	returns => {
	    type => 'array',
	    items => {
		type => "object",
		properties => {
		    pos => {
			type => 'integer',
		    }
		},
	    },
	    links => [ { rel => 'child', href => "{pos}" } ],
	},
	code => sub {
	    my ($param) = @_;

	    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

	    my ($list, $digest) = PVE::Firewall::copy_list_with_digest($rules);

	    my $ind = 0;
	    foreach my $rule (@$list) {
		$rule->{pos} = $ind++;
	    }

	    return $list;
	}});
}

sub register_get_rule {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{pos} = $api_properties->{pos};
    
    my $rule_env = $class->rule_env();

    $class->register_method({
	name => 'get_rule',
	path => '{pos}',
	method => 'GET',
	description => "Get single rule data.",
	permissions => PVE::Firewall::rules_audit_permissions($rule_env),
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	proxyto => $rule_env eq 'host' ? 'node' : undef,
	returns => {
	    type => "object",
	    properties => {
		pos => {
		    type => 'integer',
		}
	    },
	},
	code => sub {
	    my ($param) = @_;

	    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

	    my ($list, $digest) = PVE::Firewall::copy_list_with_digest($rules);
	
	    die "no rule at position $param->{pos}\n" if $param->{pos} >= scalar(@$list);
	
	    my $rule = $list->[$param->{pos}];
	    $rule->{pos} = $param->{pos};

	    return $rule;
	}});
}

sub register_create_rule {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    my $create_rule_properties = PVE::Firewall::add_rule_properties($properties);
    $create_rule_properties->{action}->{optional} = 0;
    $create_rule_properties->{type}->{optional} = 0;
    
    my $rule_env = $class->rule_env();

    $class->register_method({
	name => 'create_rule',
	path => '',
	method => 'POST',
	description => "Create new rule.",
	protected => 1,
	permissions => PVE::Firewall::rules_modify_permissions($rule_env),
	parameters => {
	    additionalProperties => 0,
	    properties => $create_rule_properties,
	},
	proxyto => $rule_env eq 'host' ? 'node' : undef,
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

	    my $rule = {};

	    PVE::Firewall::copy_rule_data($rule, $param);
	    PVE::Firewall::verify_rule($rule, $cluster_conf, $fw_conf, $class->rule_env());

	    $rule->{enable} = 0 if !defined($param->{enable});

	    unshift @$rules, $rule;

	    $class->save_rules($param, $fw_conf, $rules);

	    return undef;
	}});
}

sub register_update_rule {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{pos} = $api_properties->{pos};
    
    my $rule_env = $class->rule_env();

    $properties->{moveto} = {
	description => "Move rule to new position <moveto>. Other arguments are ignored.",
	type => 'integer',
	minimum => 0,
	optional => 1,
    };

    $properties->{delete} = {
	type => 'string', format => 'pve-configid-list',
	description => "A list of settings you want to delete.",
	optional => 1,
    };

    my $update_rule_properties = PVE::Firewall::add_rule_properties($properties);

    $class->register_method({
	name => 'update_rule',
	path => '{pos}',
	method => 'PUT',
	description => "Modify rule data.",
	protected => 1,
	permissions => PVE::Firewall::rules_modify_permissions($rule_env),
	parameters => {
	    additionalProperties => 0,
	    properties => $update_rule_properties,
	},
	proxyto => $rule_env eq 'host' ? 'node' : undef,
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

	    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($rules);
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    die "no rule at position $param->{pos}\n" if $param->{pos} >= scalar(@$rules);
	
	    my $rule = $rules->[$param->{pos}];

	    my $moveto = $param->{moveto};
	    if (defined($moveto) && $moveto != $param->{pos}) {
		my $newrules = [];
		for (my $i = 0; $i < scalar(@$rules); $i++) {
		    next if $i == $param->{pos};
		    if ($i == $moveto) {
			push @$newrules, $rule;
		    }
		    push @$newrules, $rules->[$i];
		}
		push @$newrules, $rule if $moveto >= scalar(@$rules);
		$rules = $newrules;
	    } else {
		PVE::Firewall::copy_rule_data($rule, $param);
		
		PVE::Firewall::delete_rule_properties($rule, $param->{'delete'}) if $param->{'delete'};

		PVE::Firewall::verify_rule($rule, $cluster_conf, $fw_conf, $class->rule_env());
	    }

	    $class->save_rules($param, $fw_conf, $rules);

	    return undef;
	}});
}

sub register_delete_rule {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{pos} = $api_properties->{pos};

    $properties->{digest} = get_standard_option('pve-config-digest');
    
    my $rule_env = $class->rule_env();

    $class->register_method({
	name => 'delete_rule',
	path => '{pos}',
	method => 'DELETE',
	description => "Delete rule.",
	protected => 1,
	permissions => PVE::Firewall::rules_modify_permissions($rule_env),
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	proxyto => $rule_env eq 'host' ? 'node' : undef,
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

	    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($rules);
	    PVE::Tools::assert_if_modified($digest, $param->{digest});
	
	    die "no rule at position $param->{pos}\n" if $param->{pos} >= scalar(@$rules);
	
	    splice(@$rules, $param->{pos}, 1);
	    
	    $class->save_rules($param, $fw_conf, $rules);

	    return undef;
	}});
}

sub register_handlers {
    my ($class) = @_;

    $class->register_get_rules();
    $class->register_get_rule();
    $class->register_create_rule();
    $class->register_update_rule();
    $class->register_delete_rule();
}

package PVE::API2::Firewall::GroupRules;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::API2::Firewall::RulesBase);

__PACKAGE__->additional_parameters({ group => get_standard_option('pve-security-group-name') });


sub rule_env {
    my ($class, $param) = @_;
    
    return 'group';
}

sub load_config {
    my ($class, $param) = @_;

    my $fw_conf = PVE::Firewall::load_clusterfw_conf();
    my $rules = $fw_conf->{groups}->{$param->{group}};
    die "no such security group '$param->{group}'\n" if !defined($rules);

    return (undef, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    if (!defined($rules)) {
	delete $fw_conf->{groups}->{$param->{group}};
    } else {
	$fw_conf->{groups}->{$param->{group}} = $rules;
    }

    PVE::Firewall::save_clusterfw_conf($fw_conf);
}

__PACKAGE__->register_method({
    name => 'delete_security_group',
    path => '',
    method => 'DELETE',
    description => "Delete security group.",
    protected => 1,
    permissions => {
	check => ['perm', '/', [ 'Sys.Modify' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => { 
	    group => get_standard_option('pve-security-group-name'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	    
	my (undef, $cluster_conf, $rules) = __PACKAGE__->load_config($param);

	die "Security group '$param->{group}' is not empty\n" 
	    if scalar(@$rules);

	__PACKAGE__->save_rules($param, $cluster_conf, undef);

	return undef;
    }});

__PACKAGE__->register_handlers();

package PVE::API2::Firewall::ClusterRules;

use strict;
use warnings;

use base qw(PVE::API2::Firewall::RulesBase);

sub rule_env {
    my ($class, $param) = @_;
    
    return 'cluster';
}

sub load_config {
    my ($class, $param) = @_;

    my $fw_conf = PVE::Firewall::load_clusterfw_conf();
    my $rules = $fw_conf->{rules};

    return (undef, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    $fw_conf->{rules} = $rules;
    PVE::Firewall::save_clusterfw_conf($fw_conf);
}

__PACKAGE__->register_handlers();

package PVE::API2::Firewall::HostRules;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::API2::Firewall::RulesBase);

__PACKAGE__->additional_parameters({ node => get_standard_option('pve-node')});

sub rule_env {
    my ($class, $param) = @_;
    
    return 'host';
}

sub load_config {
    my ($class, $param) = @_;

    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
    my $fw_conf = PVE::Firewall::load_hostfw_conf($cluster_conf);
    my $rules = $fw_conf->{rules};

    return ($cluster_conf, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    $fw_conf->{rules} = $rules;
    PVE::Firewall::save_hostfw_conf($fw_conf);
}

__PACKAGE__->register_handlers();

package PVE::API2::Firewall::VMRules;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::API2::Firewall::RulesBase);

__PACKAGE__->additional_parameters({ 
    node => get_standard_option('pve-node'),
    vmid => get_standard_option('pve-vmid'),				   
});

sub rule_env {
    my ($class, $param) = @_;
    
    return 'vm';
}

sub load_config {
    my ($class, $param) = @_;

    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
    my $fw_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, 'vm', $param->{vmid});
    my $rules = $fw_conf->{rules};

    return ($cluster_conf, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    $fw_conf->{rules} = $rules;
    PVE::Firewall::save_vmfw_conf($param->{vmid}, $fw_conf);
}

__PACKAGE__->register_handlers();

package PVE::API2::Firewall::CTRules;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::API2::Firewall::RulesBase);

__PACKAGE__->additional_parameters({ 
    node => get_standard_option('pve-node'),
    vmid => get_standard_option('pve-vmid'),				   
});

sub rule_env {
    my ($class, $param) = @_;
    
    return 'ct';
}

sub load_config {
    my ($class, $param) = @_;

    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
    my $fw_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, 'ct', $param->{vmid});
    my $rules = $fw_conf->{rules};

    return ($cluster_conf, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    $fw_conf->{rules} = $rules;
    PVE::Firewall::save_vmfw_conf($param->{vmid}, $fw_conf);
}

__PACKAGE__->register_handlers();

1;
