package PVE::API2::Firewall::Vnet;

use strict;
use warnings;

use Storable qw(dclone);

use PVE::Exception qw(raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RPCEnvironment;

use PVE::Firewall;
use PVE::API2::Firewall::Rules;
use PVE::API2::Firewall::Helpers;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method({
    subclass => "PVE::API2::Firewall::VnetRules",
    path => 'rules',
});

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    parameters => {
        additionalProperties => 0,
        properties => {
            vnet => get_standard_option('pve-sdn-vnet-id'),
        },
    },
    returns => {
        type => 'array',
        items => {
            type => "object",
            properties => {},
        },
        links => [{ rel => 'child', href => "{name}" }],
    },
    code => sub {
        my ($param) = @_;

        my $result = [
            { name => 'rules' }, { name => 'options' },
        ];

        return $result;
    },
});

my $option_properties = dclone($PVE::Firewall::vnet_option_properties);

my sub add_option_properties {
    my ($properties) = @_;

    foreach my $k (keys %$option_properties) {
        $properties->{$k} = $option_properties->{$k};
    }

    return $properties;
}

__PACKAGE__->register_method({
    name => 'get_options',
    path => 'options',
    method => 'GET',
    description => "Get vnet firewall options.",
    permissions => {
        description =>
            "Needs SDN.Audit or SDN.Allocate permissions on '/sdn/zones/<zone>/<vnet>'",
        user => 'all',
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            vnet => get_standard_option('pve-sdn-vnet-id'),
        },
    },
    returns => {
        type => "object",
        properties => $option_properties,
    },
    code => sub {
        my ($param) = @_;

        PVE::API2::Firewall::Helpers::check_vnet_access(
            $param->{vnet},
            ['SDN.Allocate', 'SDN.Audit'],
        );

        my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
        my $vnetfw_conf =
            PVE::Firewall::load_vnetfw_conf($cluster_conf, 'vnet', $param->{vnet});

        return PVE::Firewall::copy_opject_with_digest($vnetfw_conf->{options});
    },
});

__PACKAGE__->register_method({
    name => 'set_options',
    path => 'options',
    method => 'PUT',
    description => "Set Firewall options.",
    protected => 1,
    permissions => {
        description => "Needs SDN.Allocate permissions on '/sdn/zones/<zone>/<vnet>'",
        user => 'all',
    },
    parameters => {
        additionalProperties => 0,
        properties => add_option_properties({
            vnet => get_standard_option('pve-sdn-vnet-id'),
            delete => {
                type => 'string',
                format => 'pve-configid-list',
                description => "A list of settings you want to delete.",
                optional => 1,
            },
            digest => get_standard_option('pve-config-digest'),
        }),
    },
    returns => { type => "null" },
    code => sub {
        my ($param) = @_;

        PVE::API2::Firewall::Helpers::check_vnet_access($param->{vnet}, ['SDN.Allocate']);

        PVE::Firewall::lock_vnetfw_conf(
            $param->{vnet},
            10,
            sub {
                my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
                my $vnetfw_conf =
                    PVE::Firewall::load_vnetfw_conf($cluster_conf, 'vnet', $param->{vnet});

                my (undef, $digest) =
                    PVE::Firewall::copy_opject_with_digest($vnetfw_conf->{options});
                PVE::Tools::assert_if_modified($digest, $param->{digest});

                if ($param->{delete}) {
                    for my $opt (PVE::Tools::split_list($param->{delete})) {
                        raise_param_exc({ delete => "no such option '$opt'" })
                            if !$option_properties->{$opt};
                        delete $vnetfw_conf->{options}->{$opt};
                    }
                }

                if (defined($param->{enable})) {
                    $param->{enable} = $param->{enable} ? 1 : 0;
                }

                for my $k (keys %$option_properties) {
                    next if !defined($param->{$k});
                    $vnetfw_conf->{options}->{$k} = $param->{$k};
                }

                PVE::Firewall::save_vnetfw_conf($param->{vnet}, $vnetfw_conf);
            },
        );

        return undef;
    },
});

1;
