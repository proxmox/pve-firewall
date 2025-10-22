package PVE::API2::Firewall::RulesBase;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise raise_param_exc);

use PVE::Firewall;
use PVE::API2::Firewall::Helpers;

use base qw(PVE::RESTHandler);

my $api_properties = {
    pos => {
        description => "Rule position.",
        type => 'integer',
        minimum => 0,
    },
};

my $rule_return_properties = {
    action => {
        type => 'string',
    },
    comment => {
        type => 'string',
        optional => 1,
    },
    dest => {
        type => 'string',
        optional => 1,
    },
    dport => {
        type => 'string',
        optional => 1,
    },
    enable => {
        type => 'integer',
        optional => 1,
    },
    log => PVE::Firewall::get_standard_option(
        'pve-fw-loglevel',
        {
            description => 'Log level for firewall rule',
        },
    ),
    'icmp-type' => {
        type => 'string',
        optional => 1,
    },
    iface => {
        type => 'string',
        optional => 1,
    },
    ipversion => {
        type => 'integer',
        optional => 1,
    },
    macro => {
        type => 'string',
        optional => 1,
    },
    pos => {
        type => 'integer',
    },
    proto => {
        type => 'string',
        optional => 1,
    },
    source => {
        type => 'string',
        optional => 1,
    },
    sport => {
        type => 'string',
        optional => 1,
    },
    type => {
        type => 'string',
    },
};

=head3 check_privileges_for_method($class, $method_name, $param)

If the permission checks from the register_method() call are not sufficient,
this function can be overriden for performing additional permission checks
before API methods are executed. If the permission check fails, this function
should die with an appropriate error message. The name of the method calling
this function is provided by C<$method_name> and the parameters of the API
method are provided by C<$param>

Default implementation is a no-op to preserve backwards compatibility with
existing subclasses, since this got added later on. It preserves existing
behavior without having to change every subclass.

=cut

sub check_privileges_for_method {
    my ($class, $method_name, $param) = @_;
}

sub lock_config {
    my ($class, $param, $code) = @_;

    die "implement this in subclass";
}

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
                properties => $rule_return_properties,
            },
            links => [{ rel => 'child', href => "{pos}" }],
        },
        code => sub {
            my ($param) = @_;

            $class->check_privileges_for_method('get_rules', $param);

            my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

            my ($list, $digest) = PVE::Firewall::copy_list_with_digest($rules);

            my $ind = 0;
            foreach my $rule (@$list) {
                $rule->{pos} = $ind++;
            }

            return $list;
        },
    });
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
            properties => $rule_return_properties,
        },
        code => sub {
            my ($param) = @_;

            $class->check_privileges_for_method('get_rule', $param);

            my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

            my ($list, $digest) = PVE::Firewall::copy_list_with_digest($rules);

            die "no rule at position $param->{pos}\n" if $param->{pos} >= scalar(@$list);

            my $rule = $list->[$param->{pos}];
            $rule->{pos} = $param->{pos};

            return $rule;
        },
    });
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

            $class->check_privileges_for_method('create_rule', $param);

            $class->lock_config(
                $param,
                sub {
                    my ($param) = @_;

                    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

                    my $rule = {};

                    # reloading the scoped SDN config for verification, so users can
                    # only use IPSets they have permissions for
                    my $allowed_vms = PVE::API2::Firewall::Helpers::get_allowed_vms();
                    my $allowed_vnets = PVE::API2::Firewall::Helpers::get_allowed_vnets();
                    my $sdn_conf = PVE::Firewall::load_sdn_conf($allowed_vms, $allowed_vnets);

                    if ($cluster_conf) {
                        $cluster_conf->{sdn} = $sdn_conf;
                    } else {
                        $fw_conf->{sdn} = $sdn_conf;
                    }

                    PVE::Firewall::copy_rule_data($rule, $param);
                    PVE::Firewall::verify_rule(
                        $rule, $cluster_conf, $fw_conf, $class->rule_env(),
                    );

                    $rule->{enable} = 0 if !defined($param->{enable});

                    unshift @$rules, $rule;

                    $class->save_rules($param, $fw_conf, $rules);
                },
            );

            return undef;
        },
    });
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
        type => 'string',
        format => 'pve-configid-list',
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

            $class->check_privileges_for_method('update_rule', $param);

            $class->lock_config(
                $param,
                sub {
                    my ($param) = @_;

                    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

                    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($rules);
                    PVE::Tools::assert_if_modified($digest, $param->{digest});

                    die "no rule at position $param->{pos}\n"
                        if $param->{pos} >= scalar(@$rules);

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

                        PVE::Firewall::delete_rule_properties($rule, $param->{'delete'})
                            if $param->{'delete'};

                        # reloading the scoped SDN config for verification, so users can
                        # only use IPSets they have permissions for
                        my $allowed_vms = PVE::API2::Firewall::Helpers::get_allowed_vms();
                        my $allowed_vnets = PVE::API2::Firewall::Helpers::get_allowed_vnets();
                        my $sdn_conf =
                            PVE::Firewall::load_sdn_conf($allowed_vms, $allowed_vnets);

                        if ($cluster_conf) {
                            $cluster_conf->{sdn} = $sdn_conf;
                        } else {
                            $fw_conf->{sdn} = $sdn_conf;
                        }

                        PVE::Firewall::verify_rule(
                            $rule, $cluster_conf, $fw_conf, $class->rule_env(),
                        );
                    }

                    $class->save_rules($param, $fw_conf, $rules);
                },
            );

            return undef;
        },
    });
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

            $class->check_privileges_for_method('delete_rule', $param);

            $class->lock_config(
                $param,
                sub {
                    my ($param) = @_;

                    my ($cluster_conf, $fw_conf, $rules) = $class->load_config($param);

                    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($rules);
                    PVE::Tools::assert_if_modified($digest, $param->{digest});

                    die "no rule at position $param->{pos}\n"
                        if $param->{pos} >= scalar(@$rules);

                    splice(@$rules, $param->{pos}, 1);

                    $class->save_rules($param, $fw_conf, $rules);
                },
            );

            return undef;
        },
    });
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

sub lock_config {
    my ($class, $param, $code) = @_;

    PVE::Firewall::lock_clusterfw_conf(10, $code, $param);
}

sub load_config {
    my ($class, $param) = @_;

    my $fw_conf = PVE::Firewall::load_clusterfw_conf();
    my $rules = $fw_conf->{groups}->{ $param->{group} };
    die "no such security group '$param->{group}'\n" if !defined($rules);

    return (undef, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    if (!defined($rules)) {
        delete $fw_conf->{groups}->{ $param->{group} };
    } else {
        $fw_conf->{groups}->{ $param->{group} } = $rules;
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
        check => ['perm', '/', ['Sys.Modify']],
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

        __PACKAGE__->lock_config(
            $param,
            sub {
                my ($param) = @_;

                my (undef, $cluster_conf, $rules) = __PACKAGE__->load_config($param);

                die "Security group '$param->{group}' is not empty\n"
                    if scalar(@$rules);

                __PACKAGE__->save_rules($param, $cluster_conf, undef);
            },
        );

        return undef;
    },
});

__PACKAGE__->register_handlers();

package PVE::API2::Firewall::ClusterRules;

use strict;
use warnings;

use base qw(PVE::API2::Firewall::RulesBase);

sub rule_env {
    my ($class, $param) = @_;

    return 'cluster';
}

sub lock_config {
    my ($class, $param, $code) = @_;

    PVE::Firewall::lock_clusterfw_conf(10, $code, $param);
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

__PACKAGE__->additional_parameters({ node => get_standard_option('pve-node') });

sub rule_env {
    my ($class, $param) = @_;

    return 'host';
}

sub lock_config {
    my ($class, $param, $code) = @_;

    PVE::Firewall::lock_hostfw_conf(undef, 10, $code, $param);
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

sub lock_config {
    my ($class, $param, $code) = @_;

    PVE::Firewall::lock_vmfw_conf($param->{vmid}, 10, $code, $param);
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

sub lock_config {
    my ($class, $param, $code) = @_;

    PVE::Firewall::lock_vmfw_conf($param->{vmid}, 10, $code, $param);
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

package PVE::API2::Firewall::VnetRules;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::API2::Firewall::RulesBase);

__PACKAGE__->additional_parameters({
    vnet => get_standard_option('pve-sdn-vnet-id'),
});

sub check_privileges_for_method {
    my ($class, $method_name, $param) = @_;

    if ($method_name eq 'get_rule' || $method_name eq 'get_rules') {
        PVE::API2::Firewall::Helpers::check_vnet_access(
            $param->{vnet},
            ['SDN.Audit', 'SDN.Allocate'],
        );
    } elsif ($method_name =~ '(update|create|delete)_rule') {
        PVE::API2::Firewall::Helpers::check_vnet_access($param->{vnet}, ['SDN.Allocate']);
    } else {
        die "unknown method: $method_name";
    }
}

sub rule_env {
    my ($class, $param) = @_;

    return 'vnet';
}

sub lock_config {
    my ($class, $param, $code) = @_;

    PVE::Firewall::lock_vnetfw_conf($param->{vnet}, 10, $code, $param);
}

sub load_config {
    my ($class, $param) = @_;

    my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
    my $fw_conf = PVE::Firewall::load_vnetfw_conf($cluster_conf, 'vnet', $param->{vnet});
    my $rules = $fw_conf->{rules};

    return ($cluster_conf, $fw_conf, $rules);
}

sub save_rules {
    my ($class, $param, $fw_conf, $rules) = @_;

    $fw_conf->{rules} = $rules;
    PVE::Firewall::save_vnetfw_conf($param->{vnet}, $fw_conf);
}

__PACKAGE__->register_handlers();

1;
