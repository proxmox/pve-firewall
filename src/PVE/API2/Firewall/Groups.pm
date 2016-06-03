package PVE::API2::Firewall::Groups;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise raise_param_exc);

use PVE::Firewall;
use PVE::API2::Firewall::Rules;

use Data::Dumper; # fixme: remove

use base qw(PVE::RESTHandler);

my $get_security_group_list = sub {
    my ($cluster_conf) = @_;

    my $res = [];
    foreach my $group (sort keys %{$cluster_conf->{groups}}) {
	my $data = { 
	    group => $group,
	};
	if (my $comment = $cluster_conf->{group_comments}->{$group}) {
	    $data->{comment} = $comment;
	}
	push @$res, $data;
    }

    my ($list, $digest) = PVE::Firewall::copy_list_with_digest($res);

    return wantarray ? ($list, $digest) : $list;
};

__PACKAGE__->register_method({
    name => 'list_security_groups',
    path => '',
    method => 'GET',
    description => "List security groups.",
    permissions => { user => 'all' },
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => { 
		group => get_standard_option('pve-security-group-name'),
		digest => get_standard_option('pve-config-digest', { optional => 0} ),
		comment => { 
		    type => 'string',
		    optional => 1,
		}
	    },
	},
	links => [ { rel => 'child', href => "{group}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	return &$get_security_group_list($cluster_conf);
    }});

__PACKAGE__->register_method({
    name => 'create_security_group',
    path => '',
    method => 'POST',
    description => "Create new security group.",
    protected => 1,
    permissions => {
	check => ['perm', '/', [ 'Sys.Modify' ]],
    },
    parameters => {
	additionalProperties => 0,
	properties => { 
	    group => get_standard_option('pve-security-group-name'),
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

	if ($param->{rename}) {
	    my (undef, $digest) = &$get_security_group_list($cluster_conf);
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    raise_param_exc({ group => "Security group '$param->{rename}' does not exists" }) 
		if !$cluster_conf->{groups}->{$param->{rename}};

	    # prevent overwriting an existing group
	    raise_param_exc({ group => "Security group '$param->{group}' does already exist" })
		if $cluster_conf->{groups}->{$param->{group}} &&
		$param->{group} ne $param->{rename};

	    my $data = delete $cluster_conf->{groups}->{$param->{rename}};
	    $cluster_conf->{groups}->{$param->{group}} = $data;
	    if (my $comment = delete $cluster_conf->{group_comments}->{$param->{rename}}) {
		$cluster_conf->{group_comments}->{$param->{group}} = $comment;
	    }
	    $cluster_conf->{group_comments}->{$param->{group}} = $param->{comment} if defined($param->{comment});
	} else {
	    foreach my $name (keys %{$cluster_conf->{groups}}) {
		raise_param_exc({ group => "Security group '$name' already exists" }) 
		    if $name eq $param->{group};
	    }

	    $cluster_conf->{groups}->{$param->{group}} = [];
	    $cluster_conf->{group_comments}->{$param->{group}} = $param->{comment} if defined($param->{comment});
	}

	PVE::Firewall::save_clusterfw_conf($cluster_conf);
	
	return undef;
    }});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::GroupRules",  
    path => '{group}',
});

1;
