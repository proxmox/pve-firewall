#!/usr/bin/perl -w

use strict;
use lib qw(.);
use PVE::Firewall;

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
	},
	103 => {
	    zone => 'z1',
	    net0 => 'rtl8139=0E:9D:ED:CC:BC:ED,bridge=vmbr0',
	    net1 => 'rtl8139=0E:9D:ED:CC:BC:AA,tag=5,bridge=vmbr0',
	},
    },
};

PVE::Firewall::compile($vmdata);

exit(0);
