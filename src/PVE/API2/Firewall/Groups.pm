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

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $res = [];
	foreach my $group (keys %{$cluster_conf->{rules}}) {
	    push @$res, { name => $group, count => scalar(@{$cluster_conf->{rules}->{$group}}) };
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

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $rules = $cluster_conf->{rules}->{$param->{group}};
	die "no such security group\n" if !defined($rules);

	my $digest = $cluster_conf->{digest};

	my $res = [];

	my $ind = 0;
	foreach my $rule (@$rules) {
	    push @$res, PVE::Firewall::cleanup_fw_rule($rule, $digest, $ind++);
	}

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'get_rule',
    path => '{group}/{pos}',
    method => 'GET',
    description => "Get single rule data.",
    proxyto => 'node',
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    group => {
		description => "Security group name.",
		type => 'string',
	    },
	    pos => {
		description => "Return rule from position <pos>.",
		type => 'integer',
		minimum => 0,
	    },
	},
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

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $rules = $cluster_conf->{rules}->{$param->{group}};
	die "no such security group\n" if !defined($rules);

	my $digest = $cluster_conf->{digest};
	# fixme: check digest
	
	die "no rule at position $param->{pos}\n" if $param->{pos} >= scalar(@$rules);
	
	my $rule = $rules->[$param->{pos}];

	return PVE::Firewall::cleanup_fw_rule($rule, $digest, $param->{pos});
   }});


__PACKAGE__->register_method({
    name => 'create_rule',
    path => '{group}',
    method => 'POST',
    description => "Create new rule.",
    proxyto => 'node',
    protected => 1,
    parameters => {
    	additionalProperties => 0,
	properties => PVE::Firewall::add_rule_properties({
	    node => get_standard_option('pve-node'),
	    group => {
		description => "Security group name.",
		type => 'string',
	    },
	}),
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $rules = $cluster_conf->{rules}->{$param->{group}};
	die "no such security group\n" if !defined($rules);

	my $digest = $cluster_conf->{digest};
		
	my $rule = { type => 'out', action => 'ACCEPT', enable => 0};

	PVE::Firewall::copy_rule_data($rule, $param);

	unshift @$rules, $rule;

	PVE::Firewall::save_clusterfw_conf($cluster_conf);

	return undef;
   }});

__PACKAGE__->register_method({
    name => 'update_rule',
    path => '{group}/{pos}',
    method => 'PUT',
    description => "Modify rule data.",
    proxyto => 'node',
    protected => 1,
    parameters => {
    	additionalProperties => 0,
	properties => PVE::Firewall::add_rule_properties({
	    node => get_standard_option('pve-node'),
	    group => {
		description => "Security group name.",
		type => 'string',
	    },
	    moveto => {
		description => "Move rule to new position <moveto>. Other arguments are ignored.",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	}),
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $rules = $cluster_conf->{rules}->{$param->{group}};
	die "no such security group\n" if !defined($rules);

	my $digest = $cluster_conf->{digest};
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

	    $cluster_conf->{rules}->{$param->{group}} = $newrules;
	} else {
	    PVE::Firewall::copy_rule_data($rule, $param);
	}

	PVE::Firewall::save_clusterfw_conf($cluster_conf);

	return undef;
   }});

__PACKAGE__->register_method({
    name => 'delete_rule',
    path => '{group}/{pos}',
    method => 'DELETE',
    description => "Delete rule.",
    proxyto => 'node',
    protected => 1,
    parameters => {
    	additionalProperties => 0,
	properties => {
	    node => get_standard_option('pve-node'),
	    group => {
		description => "Security group name.",
		type => 'string',
	    },
	    pos => {
		description => "Delete rule at position <pos>.",
		type => 'integer',
		minimum => 0,
	    },
	},
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $rules = $cluster_conf->{rules}->{$param->{group}};
	die "no such security group\n" if !defined($rules);

	my $digest = $cluster_conf->{digest};
	# fixme: check digest
	
	die "no rule at position $param->{pos}\n" if $param->{pos} >= scalar(@$rules);
	
	splice(@$rules, $param->{pos}, 1);

	PVE::Firewall::save_clusterfw_conf($cluster_conf);

	return undef;
   }});

1;
