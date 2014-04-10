package PVE::API2::Firewall::Groups;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise raise_param_exc);

use PVE::Firewall;
use PVE::API2::Firewall::Rules;

use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    name => 'list_security_groups',
    path => '',
    method => 'GET',
    description => "List security groups.",
    parameters => {
    	additionalProperties => 0,
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => { 
		name => get_standard_option('pve-security-group-name'),
		digest => get_standard_option('pve-config-digest', { optional => 0} ),
		comment => { 
		    type => 'string',
		    optional => 1,
		}
	    },
	},
	links => [ { rel => 'child', href => "{name}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $digest = $cluster_conf->{digest};

	my $res = [];
	foreach my $group (keys %{$cluster_conf->{groups}}) {
	    my $data = { 
		name => $group,
		digest => $digest,
		count => scalar(@{$cluster_conf->{groups}->{$group}}) 
	    };
	    if (my $comment = $cluster_conf->{group_comments}->{$group}) {
		$data->{comment} = $comment;
	    }
	    push @$res, $data;
	}

	return $res;
    }});

__PACKAGE__->register_method({
    name => 'create_security_group',
    path => '',
    method => 'POST',
    description => "Create new security group.",
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => { 
	    name => get_standard_option('pve-security-group-name'),
	    comment => {
		type => 'string',
		optional => 1,
	    },
	    rename => get_standard_option('pve-security-group-name', {
		description => "Rename/update an existing security group. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing group.",
		optional => 1,
	    }),
	    digest => get_standard_option('pve-config-digest'),
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	my $digest = $cluster_conf->{digest};

	PVE::Tools::assert_if_modified($digest, $param->{digest});

	foreach my $name (keys %{$cluster_conf->{groups}}) {
	    raise_param_exc({ name => "Security group '$name' already exists" }) 
		if !$param->{rename} && $name eq $param->{name};
	}

	if ($param->{rename}) {
	    raise_param_exc({ name => "Security group '$param->{rename}' does not exists" }) 
		if !$cluster_conf->{groups}->{$param->{rename}};
	    my $data = delete $cluster_conf->{groups}->{$param->{rename}};
	    $cluster_conf->{groups}->{$param->{name}} = $data;
	    if (my $comment = delete $cluster_conf->{group_comments}->{$param->{rename}}) {
		$cluster_conf->{group_comments}->{$param->{name}} = $comment;
	    }
	    $cluster_conf->{group_comments}->{$param->{name}} = $param->{comment} if defined($param->{comment});
	} else {
	    $cluster_conf->{groups}->{$param->{name}} = [];
	    $cluster_conf->{group_comments}->{$param->{name}} = $param->{comment} if defined($param->{comment});
	}

	PVE::Firewall::save_clusterfw_conf($cluster_conf);
	
	return undef;
    }});

__PACKAGE__->register_method({
    name => 'delete_security_group',
    path => '{name}',
    method => 'DELETE',
    description => "Delete security group.",
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => { 
	    name => get_standard_option('pve-security-group-name'),
	    digest => get_standard_option('pve-config-digest'),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	    
	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	PVE::Tools::assert_if_modified($cluster_conf->{digest}, $param->{digest});

	return undef if !$cluster_conf->{groups}->{$param->{name}};

	die "Security group '$param->{name}' is not empty\n" 
	    if scalar(@{$cluster_conf->{groups}->{$param->{name}}});

	delete $cluster_conf->{groups}->{$param->{name}};

	PVE::Firewall::save_clusterfw_conf($cluster_conf);

	return undef;
    }});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::GroupRules",  
    path => '{group}',
});

1;
