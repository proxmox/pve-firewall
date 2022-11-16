package PVE::Firewall::Helpers;

use strict;
use warnings;

use PVE::Cluster;
use PVE::Tools qw(file_get_contents file_set_contents);

use base 'Exporter';
our @EXPORT_OK = qw(
lock_vmfw_conf
remove_vmfw_conf
clone_vmfw_conf
);

my $pvefw_conf_dir = "/etc/pve/firewall";

sub lock_vmfw_conf {
    my ($vmid, $timeout, $code, @param) = @_;

    die "can't lock VM firewall config for undefined VMID\n"
	if !defined($vmid);

    my $res = PVE::Cluster::cfs_lock_firewall("vm-$vmid", $timeout, $code, @param);
    die $@ if $@;

    return $res;
}

sub remove_vmfw_conf {
    my ($vmid) = @_;

    my $vmfw_conffile = "$pvefw_conf_dir/$vmid.fw";

    unlink $vmfw_conffile;
}

sub clone_vmfw_conf {
    my ($vmid, $newid) = @_;

    my $sourcevm_conffile = "$pvefw_conf_dir/$vmid.fw";
    my $clonevm_conffile = "$pvefw_conf_dir/$newid.fw";

    lock_vmfw_conf($newid, 10, sub {
	if (-f $clonevm_conffile) {
	    unlink $clonevm_conffile;
	}
	if (-f $sourcevm_conffile) {
	    my $data = file_get_contents($sourcevm_conffile);
	    file_set_contents($clonevm_conffile, $data);
	}
    });
}

1;
