package PVE::Firewall::Helpers;

use strict;
use warnings;

use Date::Parse qw(str2time);
use Errno qw(ENOENT);
use File::Basename qw(fileparse);
use IO::Zlib;
use PVE::Cluster;
use PVE::Network;
use PVE::Tools qw(file_get_contents file_set_contents);

use base 'Exporter';
our @EXPORT_OK = qw(
    lock_vmfw_conf
    remove_vmfw_conf
    clone_vmfw_conf
    collect_refs
    flush_fw_ct_entries_by_mark
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

sub lock_vnetfw_conf {
    my ($vnet, $timeout, $code, @param) = @_;

    die "can't lock vnet firewall config for undefined vnet\n"
        if !defined($vnet);

    my $res = PVE::Cluster::cfs_lock_firewall("vnet-$vnet", $timeout, $code, @param);
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

    lock_vmfw_conf(
        $newid,
        10,
        sub {
            if (-f $clonevm_conffile) {
                unlink $clonevm_conffile;
            }
            if (-f $sourcevm_conffile) {
                my $data = file_get_contents($sourcevm_conffile);
                file_set_contents($clonevm_conffile, $data);
            }
        },
    );
}

sub dump_fw_logfile {
    my ($filename, $param, $callback) = @_;
    my ($start, $limit, $since, $until) = $param->@{qw(start limit since until)};

    my $filter = sub {
        my ($line) = @_;

        if (defined($callback)) {
            return undef if !$callback->($line);
        }

        if ($since || $until) {
            my @words = split / /, $line;
            my $timestamp = str2time($words[3], $words[4]);
            return undef if $since && $timestamp < $since;
            return undef if $until && $timestamp > $until;
        }

        return $line;
    };

    if (!defined($since) && !defined($until)) {
        return PVE::Tools::dump_logfile($filename, $start, $limit, $filter);
    }

    my %state = (
        'count' => 0,
        'lines' => [],
        'start' => $start,
        'limit' => $limit,
    );

    # Take into consideration also rotated logs
    my ($basename, $logdir, $type) = fileparse($filename);
    my $regex = qr/^\Q$basename\E(\.[\d]+(\.gz)?)?$/;
    my @files = ();

    PVE::Tools::dir_glob_foreach(
        $logdir,
        $regex,
        sub {
            my ($file) = @_;
            push @files, $file;
        },
    );

    @files = reverse sort @files;

    my $filecount = 0;
    for my $filename (@files) {
        $state{'final'} = $filecount == $#files;
        $filecount++;

        my $fh;
        if ($filename =~ /\.gz$/) {
            $fh = IO::Zlib->new($logdir . $filename, "r");
        } else {
            $fh = IO::File->new($logdir . $filename, "r");
        }

        if (!$fh) {
            # If file vanished since reading dir entries, ignore
            next if $!{ENOENT};

            my $lines = $state{'lines'};
            my $count = ++$state{'count'};
            push @$lines, ($count, { n => $count, t => "unable to open file - $!" });
            last;
        }

        PVE::Tools::dump_logfile_by_filehandle($fh, $filter, \%state);

        close($fh);
    }

    return ($state{'count'}, $state{'lines'});
}

sub collect_refs {
    my ($conf, $type, $scope) = @_;

    my $res = [];

    if (!$type || $type eq 'ipset') {
        foreach my $name (keys %{ $conf->{ipset} }) {
            my $data = {
                type => 'ipset',
                name => $name,
                ref => "+$name",
                scope => $scope,
            };
            if (my $comment = $conf->{ipset_comments}->{$name}) {
                $data->{comment} = $comment;
            }
            push @$res, $data;
        }
    }

    if (!$type || $type eq 'alias') {
        foreach my $name (keys %{ $conf->{aliases} }) {
            my $e = $conf->{aliases}->{$name};
            my $data = {
                type => 'alias',
                name => $name,
                ref => $name,
                scope => $scope,
            };
            $data->{comment} = $e->{comment} if $e->{comment};
            push @$res, $data;
        }
    }

    return $res;
}

# This is checked in proxmox-firewall to avoid log-spam due to failing to parse the config
our $FORCE_NFT_DISABLE_FLAG_FILE = "/run/proxmox-nftables-firewall-force-disable";

=head3 is_nftables()

Checks whether nftables is active via checking for the existence of the file
C<$FORCE_NFT_DISABLE_FLAG_FILE>

=cut

sub is_nftables {
    return !-e $FORCE_NFT_DISABLE_FLAG_FILE;
}

=head3 needs_fwbr($bridge_name)

Returns whether a given bridge with interface name C<$bridge_name> requires a
firewall bridge in order for the current firewall configuration to work. This is
the case when using pve-firewall (iptables) or bridges that use OVS.

=cut

sub needs_fwbr {
    my ($bridge_name) = @_;
    return !is_nftables() || PVE::Network::is_ovs_bridge($bridge_name);
}

=head3 flush_fw_ct_entries_by_mark($mark)

Flushes all conntrack table entries which are CONNMARK'd with the given
value in C<$mark>.

=cut

sub flush_fw_ct_entries_by_mark {
    my ($mark) = @_;

    PVE::Tools::run_command(
        ['conntrack', '--delete', '--mark', $mark],
        noerr => 1,
        quiet => 1,
    );
}

1;
