package PVE::API2::Firewall::RulesBase;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;

use base qw(PVE::RESTHandler);

my $api_properties = { 
    group => {
	description => "Security group name.",
	type => 'string',
	maxLength => 20, # fixme: what length?
    },
    pos => {
	description => "Rule position.",
	type => 'integer',
	minimum => 0,
    },
};

sub load_config {
    my ($class, $param) = @_;

    die "implement this in subclass";

    #return ($fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    die "implement this in subclass";
}

my $need_group_param_hash = {};

sub need_group_param {
    my ($class, $new_value) = @_;

    $need_group_param_hash->{$class} = $new_value if defined($new_value);

    return $need_group_param_hash->{$class};
}

sub register_get_rules {
    my ($class) = @_;

    my $properties = {};

    if ($class->need_group_param()) {
	$properties->{group} = $api_properties->{group};
    } 

    $class->register_method({
	name => 'get_rules',
	path => '',
	method => 'GET',
	description => "List rules.",
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
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

	    my ($fw_conf, $rules) = $class->load_config($param);

	    my $digest = $fw_conf->{digest};

	    my $res = [];

	    my $ind = 0;
	    foreach my $rule (@$rules) {
		push @$res, PVE::Firewall::cleanup_fw_rule($rule, $digest, $ind++);
	    }

	    return $res;
	}});
}

sub register_get_rule {
    my ($class) = @_;

    my $properties = {};

    $properties->{pos} = $api_properties->{pos};
    
    if ($class->need_group_param()) {
	$properties->{group} = $api_properties->{group};
    }

    $class->register_method({
	name => 'get_rule',
	path => '{pos}',
	method => 'GET',
	description => "Get single rule data.",
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
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

	    my ($fw_conf, $rules) = $class->load_config($param);

	    my $digest = $fw_conf->{digest};
	    # fixme: check digest
	
	    die "no rule at position $param->{pos}\n" if $param->{pos} >= scalar(@$rules);
	
	    my $rule = $rules->[$param->{pos}];
	    
	    return PVE::Firewall::cleanup_fw_rule($rule, $digest, $param->{pos});
	}});
}

sub register_create_rule {
    my ($class) = @_;

    my $properties = {};

    if ($class->need_group_param()) {
	$properties->{group} = $api_properties->{group};
    }

    my $create_rule_properties = PVE::Firewall::add_rule_properties($properties);

    $class->register_method({
	name => 'create_rule',
	path => '',
	method => 'POST',
	description => "Create new rule.",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $create_rule_properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $rules) = $class->load_config($param);

	    my $digest = $fw_conf->{digest};
	    
	    my $rule = { type => 'out', action => 'ACCEPT', enable => 0};

	    PVE::Firewall::copy_rule_data($rule, $param);

	    unshift @$rules, $rule;

	    $class->save_rules($param, $fw_conf, $rules);

	    return undef;
	}});
}

sub register_update_rule {
    my ($class) = @_;

    my $properties = {};

    $properties->{pos} = $api_properties->{pos};
    
    if ($class->need_group_param()) {
	$properties->{group} = $api_properties->{group};
    }

    $properties->{moveto} = {
	description => "Move rule to new position <moveto>. Other arguments are ignored.",
	type => 'integer',
	minimum => 0,
	optional => 1,
    };

    my $update_rule_properties = PVE::Firewall::add_rule_properties($properties);

    $class->register_method({
	name => 'update_rule',
	path => '{pos}',
	method => 'PUT',
	description => "Modify rule data.",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $update_rule_properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $rules) = $class->load_config($param);

	    my $digest = $fw_conf->{digest};
	    # fixme: check digest
	
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
	    }

	    $class->save_rules($param, $fw_conf, $rules);

	    return undef;
	}});
}

sub register_delete_rule {
    my ($class) = @_;

    my $properties = {};

    $properties->{pos} = $api_properties->{pos};
    
    if ($class->need_group_param()) {
	$properties->{group} = $api_properties->{group};
    }

    $class->register_method({
	name => 'delete_rule',
	path => '{pos}',
	method => 'DELETE',
	description => "Delete rule.",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $rules) = $class->load_config($param);

	    my $digest = $fw_conf->{digest};
	    # fixme: check digest
	
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

use base qw(PVE::API2::Firewall::RulesBase);

__PACKAGE__->need_group_param(1);

sub load_config {
    my ($class, $param) = @_;

    my $fw_conf = PVE::Firewall::load_clusterfw_conf();
    my $rules = $fw_conf->{groups}->{$param->{group}};
    die "no such security group '$param->{group}'\n" if !defined($rules);

    return ($fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    $fw_conf->{groups}->{$param->{group}} = $rules;
    PVE::Firewall::save_clusterfw_conf($fw_conf);
}

__PACKAGE__->register_handlers('groups');

package PVE::API2::Firewall::ClusterRules;

use strict;
use warnings;

use base qw(PVE::API2::Firewall::RulesBase);

sub load_config {
    my ($class, $param) = @_;

    my $fw_conf = PVE::Firewall::load_clusterfw_conf();
    my $rules = $fw_conf->{rules};

    return ($fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    $fw_conf->{rules} = $rules;
    PVE::Firewall::save_clusterfw_conf($fw_conf);
}

__PACKAGE__->register_handlers('cluster');

1;
