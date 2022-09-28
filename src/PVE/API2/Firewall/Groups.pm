package PVE::API2::Firewall::Groups;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise raise_param_exc);

use PVE::Firewall;
use PVE::API2::Firewall::Rules;


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

my $rename_fw_rules = sub {
    my ($old, $new, $rules) = @_;

    for my $rule (@{$rules}) {
	next if ($rule->{type} ne "group" || $rule->{action} ne $old);
	$rule->{action} = $new;
    }
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

	my $group = $param->{group};
	my $rename = $param->{rename};
	my $comment = $param->{comment};

	PVE::Firewall::lock_clusterfw_conf(10, sub {
	    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();

	    if ($rename) {
		my (undef, $digest) = &$get_security_group_list($cluster_conf);
		PVE::Tools::assert_if_modified($digest, $param->{digest});

		raise_param_exc({ group => "Security group '$rename' does not exist" })
		    if !$cluster_conf->{groups}->{$rename};

		# prevent overwriting an existing group
		raise_param_exc({ group => "Security group '$group' does already exist" })
		    if $cluster_conf->{groups}->{$group} &&
		    $group ne $rename;

		if ($rename eq $group) {
		   $cluster_conf->{group_comments}->{$rename} = $comment if defined($comment);
		    PVE::Firewall::save_clusterfw_conf($cluster_conf);
		    return;
		}

		# Create an exact copy of the old security group
		$cluster_conf->{groups}->{$group} = $cluster_conf->{groups}->{$rename};
		$cluster_conf->{group_comments}->{$group} = $cluster_conf->{group_comments}->{$rename};

		# Update comment if provided
		$cluster_conf->{group_comments}->{$group} = $comment if defined($comment);

		# Write the copy to the cluster config, so that if something fails inbetween, the new firewall
		# rules won't be broken when the new name is referenced
		PVE::Firewall::save_clusterfw_conf($cluster_conf);

		# Update all the host configs to the new copy
		my $hosts = PVE::Cluster::get_nodelist();
		foreach my $host (@$hosts) {
		    PVE::Firewall::lock_hostfw_conf($host, 10, sub {
		        my $host_conf_path = "/etc/pve/nodes/$host/host.fw";
		        my $host_conf = PVE::Firewall::load_hostfw_conf($cluster_conf, $host_conf_path);

			if(defined($host_conf)) {
			    &$rename_fw_rules($rename,
			        $group,
			        $host_conf->{rules});
			    PVE::Firewall::save_hostfw_conf($host_conf, $host_conf_path);
		        }
		    });
		}

		# Update all the VM configs
		my $vms = PVE::Cluster::get_vmlist();
		foreach my $vm (keys %{$vms->{ids}}) {
		    PVE::Firewall::lock_vmfw_conf($vm, 10, sub {
		        my $vm_type = $vms->{ids}->{$vm}->{type} eq "lxc" ? "ct" : "vm";
		        my $vm_conf = PVE::Firewall::load_vmfw_conf($cluster_conf, $vm_type, $vm, "/etc/pve/firewall");

			if (defined($vm_conf)) {
			    &$rename_fw_rules($rename,
			        $group,
			        $vm_conf->{rules});
			    PVE::Firewall::save_vmfw_conf($vm, $vm_conf);
			}
		    });
		}

		# And also update the cluster itself
		&$rename_fw_rules($rename,
		    $group,
		    $cluster_conf->{rules});

		# Now that everything has been updated, the old rule can be deleted
		delete $cluster_conf->{groups}->{$rename};
		delete $cluster_conf->{group_comments}->{$rename};
	    } else {
		foreach my $name (keys %{$cluster_conf->{groups}}) {
		    raise_param_exc({ group => "Security group '$name' already exists" })
			if $name eq $group;
		}

		$cluster_conf->{groups}->{$group} = [];
		$cluster_conf->{group_comments}->{$group} = $comment if defined($comment);
	    }

	    PVE::Firewall::save_clusterfw_conf($cluster_conf);
	});

	return undef;
    }});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::GroupRules",
    path => '{group}',
});

1;
