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
    name => get_standard_option('ipset-name'),
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
}

sub save_ipset {
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
		    digest => get_standard_option('pve-config-digest', { optional => 0} ),	
		},
	    },
	    links => [ { rel => 'child', href => "{cidr}" } ],
	},
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $ipset) = $class->load_config($param);

	    return PVE::Firewall::copy_list_with_digest($ipset);
	}});
}

sub register_create_ip {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{cidr} = $api_properties->{cidr};
    $properties->{nomatch} = $api_properties->{nomatch};
    $properties->{comment} = $api_properties->{comment};

    $class->register_method({
	name => 'create_ip',
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

sub register_read_ip {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{cidr} = $api_properties->{cidr};
    
    $class->register_method({
	name => 'read_ip',
	path => '{cidr}',
	method => 'GET',
	description => "Read IP or Network settings from IPSet.",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "object" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $ipset) = $class->load_config($param);

	    my $list = PVE::Firewall::copy_list_with_digest($ipset);

	    foreach my $entry (@$list) {
		if ($entry->{cidr} eq $param->{cidr}) {
		    return $entry;
		}
	    }

	    raise_param_exc({ cidr => "no such IP/Network" });
	}});
}

sub register_update_ip {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{cidr} = $api_properties->{cidr};
    $properties->{nomatch} = $api_properties->{nomatch};
    $properties->{comment} = $api_properties->{comment};
    $properties->{digest} = get_standard_option('pve-config-digest');

    $class->register_method({
	name => 'update_ip',
	path => '{cidr}',
	method => 'PUT',
	description => "Update IP or Network settings",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => $properties,
	},
	returns => { type => "null" },
	code => sub {
	    my ($param) = @_;

	    my ($fw_conf, $ipset) = $class->load_config($param);

	    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($ipset);
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    foreach my $entry (@$ipset) {
		if($entry->{cidr} eq $param->{cidr}) {
		    $entry->{nomatch} = $param->{nomatch};
		    $entry->{comment} = $param->{comment};
		    $class->save_ipset($param, $fw_conf, $ipset);
		    return;
		}
	    }

	    raise_param_exc({ cidr => "no such IP/Network" });
	}});
}

sub register_delete_ip {
    my ($class) = @_;

    my $properties = $class->additional_parameters();

    $properties->{name} = $api_properties->{name};
    $properties->{cidr} = $api_properties->{cidr};
    $properties->{digest} = get_standard_option('pve-config-digest');

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

	    my (undef, $digest) = PVE::Firewall::copy_list_with_digest($ipset);
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

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
    $class->register_create_ip();
    $class->register_read_ip();
    $class->register_update_ip();
    $class->register_delete_ip();
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

package PVE::API2::Firewall::BaseIPSetList;

use strict;
use warnings;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise_param_exc);
use PVE::Firewall;

use base qw(PVE::RESTHandler);

my $get_ipset_list = sub {
    my ($fw_conf) = @_;

    my $res = [];
    foreach my $name (keys %{$fw_conf->{ipset}}) {
	my $data = { 
	    name => $name,
	};
	if (my $comment = $fw_conf->{ipset_comments}->{$name}) {
	    $data->{comment} = $comment;
	}
	push @$res, $data;
    }

    my ($list, $digest) = PVE::Firewall::copy_list_with_digest($res);

    return wantarray ? ($list, $digest) : $list;
};

sub register_index {
    my ($class) = @_;

    $class->register_method({
	name => 'ipset_index',
	path => '',
	method => 'GET',
	description => "List IPSets",
	parameters => {
	    additionalProperties => 0,
	},
	returns => {
	    type => 'array',
	    items => {
		type => "object",
		properties => { 
		    name => get_standard_option('ipset-name'),
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
	    
	    my $fw_conf = $class->load_config();

	    return &$get_ipset_list($fw_conf); 
	}});
}

sub register_create {
    my ($class) = @_;

    $class->register_method({
	name => 'create_ipset',
	path => '',
	method => 'POST',
	description => "Create new IPSet",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => { 
		name => get_standard_option('ipset-name'),
		comment => {
		    type => 'string',
		    optional => 1,
		},
		rename => get_standard_option('ipset-name', {
		    description => "Rename an existing IPSet. You can set 'rename' to the same value as 'name' to update the 'comment' of an existing IPSet.",
		    optional => 1,
		}),
		digest => get_standard_option('pve-config-digest'),
	    }
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;
	    
	    my $fw_conf = $class->load_config();

	    if ($param->{rename}) {
		my (undef, $digest) = &$get_ipset_list($fw_conf);
		PVE::Tools::assert_if_modified($digest, $param->{digest});

		raise_param_exc({ name => "IPSet '$param->{rename}' does not exists" }) 
		    if !$fw_conf->{ipset}->{$param->{rename}};

		my $data = delete $fw_conf->{ipset}->{$param->{rename}};
		$fw_conf->{ipset}->{$param->{name}} = $data;
		if (my $comment = delete $fw_conf->{ipset_comments}->{$param->{rename}}) {
		    $fw_conf->{ipset_comments}->{$param->{name}} = $comment;
		}
		$fw_conf->{ipset_comments}->{$param->{name}} = $param->{comment} if defined($param->{comment});
	    } else { 
		foreach my $name (keys %{$fw_conf->{ipset}}) {
		    raise_param_exc({ name => "IPSet '$name' already exists" }) 
			if $name eq $param->{name};
		}

		$fw_conf->{ipset}->{$param->{name}} = [];
		$fw_conf->{ipset_comments}->{$param->{name}} = $param->{comment} if defined($param->{comment});
	    }

	    $class->save_config($fw_conf);

	    return undef;
	}});
}

sub register_delete {
    my ($class) = @_;

    $class->register_method({
	name => 'delete_ipset',
	path => '{name}',
	method => 'DELETE',
	description => "Delete IPSet",
	protected => 1,
	parameters => {
	    additionalProperties => 0,
	    properties => { 
		name => get_standard_option('ipset-name'),
		digest => get_standard_option('pve-config-digest'),
	    },
	},
	returns => { type => 'null' },
	code => sub {
	    my ($param) = @_;
	    
	    my $fw_conf = $class->load_config();

	    return undef if !$fw_conf->{ipset}->{$param->{name}};

	    my (undef, $digest) = &$get_ipset_list($fw_conf);
	    PVE::Tools::assert_if_modified($digest, $param->{digest});

	    die "IPSet '$param->{name}' is not empty\n" 
		if scalar(@{$fw_conf->{ipset}->{$param->{name}}});

	    delete $fw_conf->{ipset}->{$param->{name}};

	    $class->save_config($fw_conf);

	    return undef;
	}});
}

sub register_handlers {
    my ($class) = @_;

    $class->register_index();
    $class->register_create();
    $class->register_delete();
}

package PVE::API2::Firewall::ClusterIPSetList;

use strict;
use warnings;
use PVE::Firewall;

use base qw(PVE::API2::Firewall::BaseIPSetList);

sub load_config {
    my ($class) = @_;
 
    return PVE::Firewall::load_clusterfw_conf();
}

sub save_config {
    my ($class, $fw_conf) = @_;

    PVE::Firewall::save_clusterfw_conf($fw_conf);
}

__PACKAGE__->register_handlers();

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Firewall::ClusterIPset",  
    path => '{name}',
    # set fragment delimiter (no subdirs) - we need that, because CIDR address contain a slash '/' 
    fragmentDelimiter => '', 
});

1;
