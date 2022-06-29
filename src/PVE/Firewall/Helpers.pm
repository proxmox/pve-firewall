package PVE::Firewall::Helpers;

use strict;
use warnings;

use PVE::Tools qw(file_get_contents file_set_contents);

use base 'Exporter';
our @EXPORT_OK = qw(
remove_vmfw_conf
clone_vmfw_conf
);

my $pvefw_conf_dir = "/etc/pve/firewall";

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