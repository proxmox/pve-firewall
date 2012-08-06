#!/usr/bin/perl -w

use strict;
use lib qw(.);
use PVE::Firewall;
use File::Path;
use IO::File;


my $vmdata = {
    qemu => {
	100 => {
	    net0 => 'rtl8139=9A:42:2D:0C:01:FF,bridge=vmbr0',
	},
	101 => {
	    net0 => 'rtl8139=0E:9D:ED:CC:9B:ED,bridge=vmbr0',
	},
	102 => {
	    zone => 'z1',
	    net0 => 'rtl8139=0E:9D:ED:CC:AA:ED,bridge=vmbr0',
	    net1 => 'rtl8139=0E:9D:ED:CC:CC:ED,bridge=vmbr1',
	},
	103 => {
	    zone => 'z1',
	    net0 => 'rtl8139=0E:9D:ED:CC:BC:ED,bridge=vmbr0',
	    net1 => 'rtl8139=0E:9D:ED:CC:BC:AA,tag=5,bridge=vmbr0',
	},
    },
};

sub parse_fw_rules {
    my ($filename, $fh) = @_;

    my $section;

    my $res = { in => [], out => [] };

    while (defined(my $line = <$fh>)) {
	next if $line =~ m/^#/;
	next if $line =~ m/^\s*$/;

	if ($line =~ m/^\[(in|out)\]\s*$/i) {
	    $section = lc($1);
	    next;
	}
	next if !$section;

	my ($action, $iface, $source, $dest, $proto, $dport, $sport) =
	    split(/\s+/, $line);

	if (!($action && $iface && $source && $dest)) {
	    warn "skip incomplete line\n";
	    next;
	}

	if ($action !~ m/^(ACCEPT|DROP)$/) {
	    warn "unknown action '$action'\n";
	    next;
	}

	if ($iface !~ m/^(all|net0|net1|net2|net3|net4|net5)$/) {
	    warn "unknown interface '$iface'\n";
	    next;
	}

	if ($proto && $proto !~ m/^(icmp|tcp|udp)$/) {
	    warn "unknown protokol '$proto'\n";
	    next;
	}

	if ($source !~ m/^(any)$/) {
	    warn "unknown source '$source'\n";
	    next;
	}

	if ($dest !~ m/^(any)$/) {
	    warn "unknown destination '$dest'\n";
	    next;
	}

	my $rule = {
	    action => $action,
	    iface => $iface,
	    source => $source,
	    dest => $dest,
	    proto => $proto,
	    dport => $dport,
	    sport => $sport,
	};

	push @{$res->{$section}}, $rule;
    }

    return $res;
}

my $testdir = "./testdir";
rmtree($testdir);
mkdir $testdir;

my $rules = {};
foreach my $vmid (keys %{$vmdata->{qemu}}) {
    my $filename = "config/$vmid.fw";
    my $fh = IO::File->new($filename, O_RDONLY);
    next if !$fh;

    $rules->{$vmid} = parse_fw_rules($filename, $fh);
}

PVE::Firewall::compile($testdir, $vmdata, $rules);

PVE::Tools::run_command(['shorewall', 'check', $testdir]);

exit(0);
