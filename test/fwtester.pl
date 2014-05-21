#!/usr/bin/perl

use lib '../src';
use strict;
use warnings;
use Data::Dumper;
use PVE::FirewallSimulator;
use Getopt::Long;
use File::Basename;
use Net::IP;

my $debug = 0;

sub print_usage_and_exit {
    die "usage: $0 [--debug] [testfile [testid]]\n";
}

if (!GetOptions ('debug' => \$debug)) {
    print_usage_and_exit();
}

PVE::FirewallSimulator::debug($debug);
 
my $testfilename = shift;
my $testid = shift;

sub run_tests {
    my ($vmdata, $testdir, $testfile, $testid) = @_;

    $testfile = 'tests' if !$testfile;


    $vmdata->{testdir} = $testdir;

    my $host_ip = '172.16.1.2';

    PVE::Firewall::local_network('172.16.1.0/24');

    my ($ruleset, $ipset_ruleset) = 
	PVE::Firewall::compile(undef, undef, $vmdata);

    my $filename = "$testdir/$testfile";
    my $fh = IO::File->new($filename) ||
	die "unable to open '$filename' - $!\n";

    my $testcount = 0;
    while (defined(my $line = <$fh>)) {
	next if $line =~ m/^\s*$/;
	next if $line =~ m/^#.*$/;
	if ($line =~ m/^\{.*\}\s*$/) {
	    my $test = eval $line;
	    die $@ if $@;
	    next if defined($testid) && (!defined($test->{id}) || ($testid ne $test->{id}));
	    PVE::FirewallSimulator::reset_trace();
	    print Dumper($ruleset) if $debug;
	    $testcount++;
	    eval {
		my @test_zones = qw(host outside nfvm vm100 ct200);
		if (!defined($test->{from}) && !defined($test->{to})) {
		    die "missing zone speification (from, to)\n";
		} elsif (!defined($test->{to})) {
		    foreach my $zone (@test_zones) {
			next if $zone eq $test->{from};
			$test->{to} = $zone;
			PVE::FirewallSimulator::add_trace("Set Zone: to => '$zone'\n"); 
			PVE::FirewallSimulator::simulate_firewall($ruleset, $ipset_ruleset, 
								  $host_ip, $vmdata, $test);
		    }
		} elsif (!defined($test->{from})) {
		    foreach my $zone (@test_zones) {
			next if $zone eq $test->{to};
			$test->{from} = $zone;
			PVE::FirewallSimulator::add_trace("Set Zone: from => '$zone'\n"); 
			PVE::FirewallSimulator::simulate_firewall($ruleset, $ipset_ruleset, 
								  $host_ip, $vmdata, $test);
		    }
		} else {
		    PVE::FirewallSimulator::simulate_firewall($ruleset, $ipset_ruleset, 
							      $host_ip, $vmdata, $test);
		}
	    };
	    if (my $err = $@) {

		print Dumper($ruleset) if !$debug;

		print PVE::FirewallSimulator::get_trace() . "\n" if !$debug;

		print "$filename line $.: $line";

		print "test failed: $err\n";

		exit(-1);
	    }
	} else {
	    die "parse error";
	}
    }

    die "no tests found\n" if $testcount <= 0;

    print "PASS: $filename\n";

    return undef;
}

my $vmdata = {
    qemu => {
	100 => {
	    net0 => "e1000=0E:0B:38:B8:B3:21,bridge=vmbr0,firewall=1",
	},
	101 => {
	    net0 => "e1000=0E:0B:38:B8:B3:22,bridge=vmbr0,firewall=1",
	},
	# on bridge vmbr1
	110 => {
	    net0 => "e1000=0E:0B:38:B8:B4:21,bridge=vmbr1,firewall=1",
	},
    },
    openvz => {
	200 => {
	    ip_address => { value => '10.0.200.1' },
	},
	201 => {
	    ip_address => { value => '10.0.200.2' },
	},
    },
};

if ($testfilename) {
    my $testfile;
    my $dir;

    if (-d $testfilename) {
	$dir = $testfilename;
    } elsif (-f $testfilename) {
	$dir = dirname($testfilename);
	$testfile = basename($testfilename);
    } else {
	die "no such file/dir '$testfilename'\n"; 
    }

    run_tests($vmdata, $dir, $testfile, $testid);

} else { 
    foreach my $dir (<test-*>) {
	next if ! -d $dir;
	run_tests($vmdata, $dir);
    }
}

print "OK - all tests passed\n";

exit(0);
