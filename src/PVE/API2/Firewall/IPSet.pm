package PVE::API2::Firewall::IPSetBase;

use strict;
use warnings;
use PVE::Exception qw(raise raise_param_exc);
use PVE::JSONSchema qw(get_standard_option);

use PVE::Firewall;

use base qw(PVE::RESTHandler);

my $api_properties = { 
    cidr => {
	description => "Network/IP specification in CIDR format.",
	type => 'string', format => 'IPv4orCIDR',
    },
    name => {
	description => "IP set name.",
	type => 'string',
    },
    comment => {
	type => 'string',
	optional => 1,
    },
    nomatch => {
	type => 'boolean',
	optional => 1,
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

sub register_get_ipset {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};

    $class->register_method({
	name => 'get_ipset',
	path => '',
	method => 'GET',
	description => "List IPSet content",
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => {
	    type => 'array',
	    items => {
		type => "object",
		properties => {
		    cidr => {
			type => 'string',
		    },
		    comment => {
			type => 'string',
			optional => 1,
		    },
		    nomatch => {
			type => 'boolean',
			optional => 1,
		    },			
		},
	    },
	    links => [ { rel => 'child', href => "{cidr}" } ],
	},
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $ipset) = $class->load_config($param);

	    return $ipset;
	}});
}

sub register_add_ip {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{cidr} = $api_properties->{cidr};
    $properties->{nomatch} = $api_properties->{nomatch};
    $properties->{comment} = $api_properties->{comment};
    
    $class->register_method({
	name => 'add_ip',
	path => '',
	method => 'POST',
	description => "Add IP or Network to IPSet.",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $ipset) = $class->load_config($param);

	    my $cidr = $param->{cidr};
	    
	    foreach my $entry (@$ipset) {
		raise_param_exc({ cidr => "address '$cidr' already exists" }) 
		    if $entry->{cidr} eq $cidr;
	    }

	    my $data = { cidr => $cidr };
	    $data->{nomatch} = 1 if $param->{nomatch};
	    $data->{comment} = $param->{comment} if $param->{comment};

	    unshift @$ipset, $data;

	    $class->save_ipset($param, $fw_conf, $ipset);

	    return undef;
	}});
}

sub register_remove_ip {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{cidr} = $api_properties->{cidr};
    
    $class->register_method({
	name => 'remove_ip',
	path => '{cidr}',
	method => 'DELETE',
	description => "Remove IP or Network from IPSet.",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $ipset) = $class->load_config($param);

	    my $new = [];
   
	    foreach my $entry (@$ipset) {
		push @$new, $entry if $entry->{cidr} ne $param->{cidr};
	    }

	    $class->save_ipset($param, $fw_conf, $new);
	    
	    return undef;
	}});
}

sub register_handlers {
    my ($class) = @_;

    $class->register_get_ipset();
    $class->register_add_ip();
    $class->register_remove_ip();
}

package PVE::API2::Firewall::ClusterIPset;

use strict;
use warnings;

use base qw(PVE::API2::Firewall::IPSetBase);

sub load_config {
    my ($class, $param) = @_;

    my $fw_conf = PVE::Firewall::load_clusterfw_conf();
    my $ipset = $fw_conf->{ipset}->{$param->{name}};
    die "no such IPSet '$param->{name}'\n" if !defined($ipset);

    return ($fw_conf, $ipset);
}

sub save_ipset {
    my ($class, $param, $fw_conf, $ipset) = @_;

    $fw_conf->{ipset}->{$param->{name}} = $ipset;
    PVE::Firewall::save_clusterfw_conf($fw_conf);
}

__PACKAGE__->register_handlers();

1;
