#!/usr/bin/perl

use lib '../src';

use strict;
use warnings;

use Data::Dumper;
use File::Basename;
use Getopt::Long;
use Net::IP;

use PVE::Corosync;
use PVE::FirewallSimulator;
use PVE::INotify;

my $debug = 0;

sub print_usage_and_exit {
    die "usage: $0 [--debug] [testfile [testid]]\n";
}

if (!GetOptions('debug' => \$debug)) {
    print_usage_and_exit();
}

# load dummy corosync config to have fw create according rules
my $corosync_conf_fn = "corosync.conf";
my $raw = PVE::Tools::file_get_contents($corosync_conf_fn);
my $local_hostname = PVE::INotify::nodename();
(my $raw_replaced = $raw) =~ s/proxself$/$local_hostname\n/gm;
my $corosync_conf = PVE::Corosync::parse_conf($corosync_conf_fn, $raw_replaced);

PVE::FirewallSimulator::debug($debug);

my $testfilename = shift;
my $testid = shift;

sub run_tests {
    my ($vmdata, $testdir, $testfile, $testid) = @_;

    $testfile = 'tests' if !$testfile;

    $vmdata->{testdir} = $testdir;

    my $host_ip = '172.16.1.2';

    PVE::Firewall::local_network('172.16.1.0/24');

    my ($ruleset, $ipset_ruleset) = PVE::Firewall::compile(undef, undef, $vmdata, $corosync_conf);

    my $filename = "$testdir/$testfile";
    my $fh = IO::File->new($filename)
        || die "unable to open '$filename' - $!\n";

    my $testcount = 0;
    while (defined(my $line = <$fh>)) {
        next if $line =~ m/^\s*$/;
        next if $line =~ m/^#.*$/;
        if ($line =~ m/^\{.*\}\s*$/) {
            my $test = eval $line;
            die $@ if $@;
            next if defined($testid) && (!defined($test->{id}) || ($testid ne $test->{id}));
            PVE::FirewallSimulator::reset_trace();
            print Dumper($ruleset->{filter}) if $debug;
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
                        PVE::FirewallSimulator::simulate_firewall(
                            $ruleset->{filter}, $ipset_ruleset, $host_ip, $vmdata, $test,
                        );
                    }
                } elsif (!defined($test->{from})) {
                    foreach my $zone (@test_zones) {
                        next if $zone eq $test->{to};
                        $test->{from} = $zone;
                        PVE::FirewallSimulator::add_trace("Set Zone: from => '$zone'\n");
                        PVE::FirewallSimulator::simulate_firewall(
                            $ruleset->{filter}, $ipset_ruleset, $host_ip, $vmdata, $test,
                        );
                    }
                } else {
                    PVE::FirewallSimulator::simulate_firewall(
                        $ruleset->{filter}, $ipset_ruleset, $host_ip, $vmdata, $test,
                    );
                }
            };
            if (my $err = $@) {
                print Dumper($ruleset->{filter}) if !$debug;
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
            net1 => "e1000=0E:0B:38:B9:B4:21,bridge=vmbr1,firewall=1",
            net2 => "e1000=0E:0B:38:BA:B4:21,bridge=vmbr2,firewall=1",
        },
        101 => {
            net0 => "e1000=0E:0B:38:B8:B3:22,bridge=vmbr0,firewall=1",
        },
        # on bridge vmbr1
        110 => {
            net0 => "e1000=0E:0B:38:B8:B4:21,bridge=vmbr1,firewall=1",
        },
    },
    lxc => {
        200 => {
            net0 =>
                "name=eth0,hwaddr=0E:18:24:41:2C:43,bridge=vmbr0,firewall=1,ip=10.0.200.1/24",
        },
        201 => {
            net0 =>
                "name=eth0,hwaddr=0E:18:24:41:2C:44,bridge=vmbr0,firewall=1,ip=10.0.200.2/24",
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
        next if !-d $dir;
        run_tests($vmdata, $dir);
    }
}

print "OK - all tests passed\n";

exit(0);
