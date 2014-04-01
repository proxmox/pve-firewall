package PVE::Firewall;

use warnings;
use strict;
use Data::Dumper;
use Digest::SHA;
use PVE::INotify;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;
use PVE::ProcFSTools;
use PVE::Tools;
use File::Basename;
use File::Path;
use IO::File;
use Net::IP;
use PVE::Tools qw(run_command lock_file);
use Encode;

my $clusterfw_conf_filename = "/etc/pve/firewall/cluster.fw";

# dynamically include PVE::QemuServer and PVE::OpenVZ 
# to avoid dependency problems
my $have_qemu_server;
eval {
    require PVE::QemuServer;
    $have_qemu_server = 1;
};

my $have_pve_manager;
eval {
    require PVE::OpenVZ;
    $have_pve_manager = 1;
};

use Data::Dumper;

my $nodename = PVE::INotify::nodename();

my $pve_fw_lock_filename = "/var/lock/pvefw.lck";
my $pve_fw_status_filename = "/var/lib/pve-firewall/pvefw.status";

my $default_log_level = 'info';

my $log_level_hash = {
    debug => 7,
    info => 6,
    notice => 5,
    warning => 4,
    err => 3,
    crit => 2,
    alert => 1,
    emerg => 0,
};

# imported/converted from: /usr/share/shorewall/macro.*
my $pve_fw_macros = {
    'Amanda' => [
	{ action => 'PARAM', proto => 'udp', dport => '10080' },
	{ action => 'PARAM', proto => 'tcp', dport => '10080' },
    ],
    'Auth' => [
	{ action => 'PARAM', proto => 'tcp', dport => '113' },
    ],
    'BGP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '179' },
    ],
    'BitTorrent' => [
	{ action => 'PARAM', proto => 'tcp', dport => '6881:6889' },
	{ action => 'PARAM', proto => 'udp', dport => '6881' },
    ],
    'BitTorrent32' => [
	{ action => 'PARAM', proto => 'tcp', dport => '6881:6999' },
	{ action => 'PARAM', proto => 'udp', dport => '6881' },
    ],
    'CVS' => [
	{ action => 'PARAM', proto => 'tcp', dport => '2401' },
    ],
    'Citrix' => [
	{ action => 'PARAM', proto => 'tcp', dport => '1494' },
	{ action => 'PARAM', proto => 'udp', dport => '1604' },
	{ action => 'PARAM', proto => 'tcp', dport => '2598' },
    ],
    'DAAP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '3689' },
	{ action => 'PARAM', proto => 'udp', dport => '3689' },
    ],
    'DCC' => [
	{ action => 'PARAM', proto => 'tcp', dport => '6277' },
    ],
    'DHCPfwd' => [
	{ action => 'PARAM', proto => 'udp', dport => '67:68', sport => '67:68' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '67:68', sport => '67:68' },
    ],
    'DNS' => [
	{ action => 'PARAM', proto => 'udp', dport => '53' },
	{ action => 'PARAM', proto => 'tcp', dport => '53' },
    ],
    'Distcc' => [
	{ action => 'PARAM', proto => 'tcp', dport => '3632' },
    ],
    'Edonkey' => [
	{ action => 'PARAM', proto => 'tcp', dport => '4662' },
	{ action => 'PARAM', proto => 'udp', dport => '4665' },
    ],
    'FTP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '21' },
    ],
    'Finger' => [
	{ action => 'PARAM', proto => 'tcp', dport => '79' },
    ],
    'GNUnet' => [
	{ action => 'PARAM', proto => 'tcp', dport => '2086' },
	{ action => 'PARAM', proto => 'udp', dport => '2086' },
	{ action => 'PARAM', proto => 'tcp', dport => '1080' },
	{ action => 'PARAM', proto => 'udp', dport => '1080' },
    ],
    'GRE' => [
	{ action => 'PARAM', proto => '47' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => '47' },
    ],
    'Git' => [
	{ action => 'PARAM', proto => 'tcp', dport => '9418' },
    ],
    'Gnutella' => [
	{ action => 'PARAM', proto => 'tcp', dport => '6346' },
	{ action => 'PARAM', proto => 'udp', dport => '6346' },
    ],
    'HKP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '11371' },
    ],
    'HTTP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '80' },
    ],
    'HTTPS' => [
	{ action => 'PARAM', proto => 'tcp', dport => '443' },
    ],
    'ICPV2' => [
	{ action => 'PARAM', proto => 'udp', dport => '3130' },
    ],
    'ICQ' => [
	{ action => 'PARAM', proto => 'tcp', dport => '5190' },
    ],
    'IMAP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '143' },
    ],
    'IMAPS' => [
	{ action => 'PARAM', proto => 'tcp', dport => '993' },
    ],
    'IPIP' => [
	{ action => 'PARAM', proto => '94' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => '94' },
    ],
    'IPP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '631' },
    ],
    'IPPbrd' => [
	{ action => 'PARAM', proto => 'udp', dport => '631' },
    ],
    'IPPserver' => [
	{ action => 'PARAM', source => 'SOURCE', dest => 'DEST', proto => 'tcp', dport => '631' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '631' },
    ],
    'IPsec' => [
	{ action => 'PARAM', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', proto => '50' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => '50' },
    ],
    'IPsecah' => [
	{ action => 'PARAM', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', proto => '51' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => '51' },
    ],
    'IPsecnat' => [
	{ action => 'PARAM', proto => 'udp', dport => '500' },
	{ action => 'PARAM', proto => 'udp', dport => '4500' },
	{ action => 'PARAM', proto => '50' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '500' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '4500' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => '50' },
    ],
    'IRC' => [
	{ action => 'PARAM', proto => 'tcp', dport => '6667' },
    ],
    'JabberPlain' => [
	{ action => 'PARAM', proto => 'tcp', dport => '5222' },
    ],
    'JabberSecure' => [
	{ action => 'PARAM', proto => 'tcp', dport => '5223' },
    ],
    'Jabberd' => [
	{ action => 'PARAM', proto => 'tcp', dport => '5269' },
    ],
    'Jetdirect' => [
	{ action => 'PARAM', proto => 'tcp', dport => '9100' },
    ],
    'L2TP' => [
	{ action => 'PARAM', proto => 'udp', dport => '1701' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '1701' },
    ],
    'LDAP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '389' },
    ],
    'LDAPS' => [
	{ action => 'PARAM', proto => 'tcp', dport => '636' },
    ],
    'MSNP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '1863' },
    ],
    'MSSQL' => [
	{ action => 'PARAM', proto => 'tcp', dport => '1433' },
    ],
    'Mail' => [
	{ action => 'PARAM', proto => 'tcp', dport => '25' },
	{ action => 'PARAM', proto => 'tcp', dport => '465' },
	{ action => 'PARAM', proto => 'tcp', dport => '587' },
    ],
    'Munin' => [
	{ action => 'PARAM', proto => 'tcp', dport => '4949' },
    ],
    'MySQL' => [
	{ action => 'PARAM', proto => 'tcp', dport => '3306' },
    ],
    'NNTP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '119' },
    ],
    'NNTPS' => [
	{ action => 'PARAM', proto => 'tcp', dport => '563' },
    ],
    'NTP' => [
	{ action => 'PARAM', proto => 'udp', dport => '123' },
    ],
    'NTPbi' => [
	{ action => 'PARAM', proto => 'udp', dport => '123' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '123' },
    ],
    'NTPbrd' => [
	{ action => 'PARAM', proto => 'udp', dport => '123' },
	{ action => 'PARAM', proto => 'udp', dport => '1024:65535', sport => '123' },
    ],
    'OSPF' => [
	{ action => 'PARAM', proto => '89' },
    ],
    'OpenVPN' => [
	{ action => 'PARAM', proto => 'udp', dport => '1194' },
    ],
    'PCA' => [
	{ action => 'PARAM', proto => 'udp', dport => '5632' },
	{ action => 'PARAM', proto => 'tcp', dport => '5631' },
    ],
    'POP3' => [
	{ action => 'PARAM', proto => 'tcp', dport => '110' },
    ],
    'POP3S' => [
	{ action => 'PARAM', proto => 'tcp', dport => '995' },
    ],
    'PPtP' => [
	{ action => 'PARAM', proto => '47' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => '47' },
	{ action => 'PARAM', proto => 'tcp', dport => '1723' },
    ],
    'Ping' => [
	{ action => 'PARAM', proto => 'icmp', dport => 'echo-request' },
    ],
    'PostgreSQL' => [
	{ action => 'PARAM', proto => 'tcp', dport => '5432' },
    ],
    'Printer' => [
	{ action => 'PARAM', proto => 'tcp', dport => '515' },
    ],
    'RDP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '3389' },
    ],
    'RIPbi' => [
	{ action => 'PARAM', proto => 'udp', dport => '520' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '520' },
    ],
    'RNDC' => [
	{ action => 'PARAM', proto => 'tcp', dport => '953' },
    ],
    'Razor' => [
	{ action => 'ACCEPT', proto => 'tcp', dport => '2703' },
    ],
    'Rdate' => [
	{ action => 'PARAM', proto => 'tcp', dport => '37' },
    ],
    'Rsync' => [
	{ action => 'PARAM', proto => 'tcp', dport => '873' },
    ],
    'SANE' => [
	{ action => 'PARAM', proto => 'tcp', dport => '6566' },
    ],
    'SMB' => [
	{ action => 'PARAM', proto => 'udp', dport => '135,445' },
	{ action => 'PARAM', proto => 'udp', dport => '137:139' },
	{ action => 'PARAM', proto => 'udp', dport => '1024:65535', sport => '137' },
	{ action => 'PARAM', proto => 'tcp', dport => '135,139,445' },
    ],
    'SMBBI' => [
	{ action => 'PARAM', proto => 'udp', dport => '135,445' },
	{ action => 'PARAM', proto => 'udp', dport => '137:139' },
	{ action => 'PARAM', proto => 'udp', dport => '1024:65535', sport => '137' },
	{ action => 'PARAM', proto => 'tcp', dport => '135,139,445' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '135,445' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '137:139' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'udp', dport => '1024:65535', sport => '137' },
	{ action => 'PARAM', source => 'DEST', dest => 'SOURCE', proto => 'tcp', dport => '135,139,445' },
    ],
    'SMBswat' => [
	{ action => 'PARAM', proto => 'tcp', dport => '901' },
    ],
    'SMTP' => [
	{ action => 'PARAM', proto => 'tcp', dport => '25' },
    ],
    'SMTPS' => [
	{ action => 'PARAM', proto => 'tcp', dport => '465' },
    ],
    'SNMP' => [
	{ action => 'PARAM', proto => 'udp', dport => '161:162' },
	{ action => 'PARAM', proto => 'tcp', dport => '161' },
    ],
    'SPAMD' => [
	{ action => 'PARAM', proto => 'tcp', dport => '783' },
    ],
    'SSH' => [
	{ action => 'PARAM', proto => 'tcp', dport => '22' },
    ],
    'SVN' => [
	{ action => 'PARAM', proto => 'tcp', dport => '3690' },
    ],
    'SixXS' => [
	{ action => 'PARAM', proto => 'tcp', dport => '3874' },
	{ action => 'PARAM', proto => 'udp', dport => '3740' },
	{ action => 'PARAM', proto => '41' },
	{ action => 'PARAM', proto => 'udp', dport => '5072,8374' },
    ],
    'Squid' => [
	{ action => 'PARAM', proto => 'tcp', dport => '3128' },
    ],
    'Submission' => [
	{ action => 'PARAM', proto => 'tcp', dport => '587' },
    ],
    'Syslog' => [
	{ action => 'PARAM', proto => 'udp', dport => '514' },
	{ action => 'PARAM', proto => 'tcp', dport => '514' },
    ],
    'TFTP' => [
	{ action => 'PARAM', proto => 'udp', dport => '69' },
    ],
    'Telnet' => [
	{ action => 'PARAM', proto => 'tcp', dport => '23' },
    ],
    'Telnets' => [
	{ action => 'PARAM', proto => 'tcp', dport => '992' },
    ],
    'Time' => [
	{ action => 'PARAM', proto => 'tcp', dport => '37' },
    ],
    'Trcrt' => [
	{ action => 'PARAM', proto => 'udp', dport => '33434:33524' },
	{ action => 'PARAM', proto => 'icmp', dport => 'echo-request' },
    ],
    'VNC' => [
	{ action => 'PARAM', proto => 'tcp', dport => '5900:5909' },
    ],
    'VNCL' => [
	{ action => 'PARAM', proto => 'tcp', dport => '5500' },
    ],
    'Web' => [
	{ action => 'PARAM', proto => 'tcp', dport => '80' },
	{ action => 'PARAM', proto => 'tcp', dport => '443' },
    ],
    'Webcache' => [
	{ action => 'PARAM', proto => 'tcp', dport => '8080' },
    ],
    'Webmin' => [
	{ action => 'PARAM', proto => 'tcp', dport => '10000' },
    ],
    'Whois' => [
	{ action => 'PARAM', proto => 'tcp', dport => '43' },
    ],
};

my $pve_fw_parsed_macros;
my $pve_fw_preferred_macro_names = {};

my $pve_std_chains = {
    'PVEFW-SET-ACCEPT-MARK' => [
	"-j MARK --set-mark 1",
    ],
    'PVEFW-DropBroadcast' => [
	# same as shorewall 'Broadcast'
	# simply DROP BROADCAST/MULTICAST/ANYCAST
	# we can use this to reduce logging
	{ action => 'DROP', dsttype => 'BROADCAST' },
	{ action => 'DROP', dsttype => 'MULTICAST' },
	{ action => 'DROP', dsttype => 'ANYCAST' },
	{ action => 'DROP', dest => '224.0.0.0/4' }, 
    ],
    'PVEFW-reject' => [
	# same as shorewall 'reject'
	{ action => 'DROP', dsttype => 'BROADCAST' },
	{ action => 'DROP', source => '224.0.0.0/4' }, 
	{ action => 'DROP', proto => 'icmp' },
	"-p tcp -j REJECT --reject-with tcp-reset",
	"-p udp -j REJECT --reject-with icmp-port-unreachable",
	"-p icmp -j REJECT --reject-with icmp-host-unreachable",
	"-j REJECT --reject-with icmp-host-prohibited",
    ],
    'PVEFW-Drop' => [
	# same as shorewall 'Drop', which is equal to DROP, 
	# but REJECT/DROP some packages to reduce logging,
	# and ACCEPT critical ICMP types
	{ action => 'PVEFW-reject',  proto => 'tcp', dport => '43' }, # REJECT 'auth'
	# we are not interested in BROADCAST/MULTICAST/ANYCAST
	{ action => 'PVEFW-DropBroadcast' },
	# ACCEPT critical ICMP types
	{ action => 'ACCEPT', proto => 'icmp', dport => 'fragmentation-needed' },
	{ action => 'ACCEPT', proto => 'icmp', dport => 'time-exceeded' },
	# Drop packets with INVALID state
	"-m conntrack --ctstate INVALID -j DROP",
	# Drop Microsoft SMB noise
	{ action => 'DROP', proto => 'udp', dport => '135,445', nbdport => 2 },
	{ action => 'DROP', proto => 'udp', dport => '137:139'},
	{ action => 'DROP', proto => 'udp', dport => '1024:65535', sport => 137 },
	{ action => 'DROP', proto => 'tcp', dport => '135,139,445', nbdport => 3 },
	{ action => 'DROP', proto => 'udp', dport => 1900 }, # UPnP
	# Drop new/NotSyn traffic so that it doesn't get logged
	"-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
	# Drop DNS replies
	{ action => 'DROP', proto => 'udp', sport => 53 },
    ],
    'PVEFW-Reject' => [
	# same as shorewall 'Reject', which is equal to Reject, 
	# but REJECT/DROP some packages to reduce logging,
	# and ACCEPT critical ICMP types
	{ action => 'PVEFW-reject',  proto => 'tcp', dport => '43' }, # REJECT 'auth'
	# we are not interested in BROADCAST/MULTICAST/ANYCAST
	{ action => 'PVEFW-DropBroadcast' },
	# ACCEPT critical ICMP types
	{ action => 'ACCEPT', proto => 'icmp', dport => 'fragmentation-needed' },
	{ action => 'ACCEPT', proto => 'icmp', dport => 'time-exceeded' },
	# Drop packets with INVALID state
	"-m conntrack --ctstate INVALID -j DROP",
	# Drop Microsoft SMB noise
	{ action => 'PVEFW-reject', proto => 'udp', dport => '135,445', nbdport => 2 },
	{ action => 'PVEFW-reject', proto => 'udp', dport => '137:139'},
	{ action => 'PVEFW-reject', proto => 'udp', dport => '1024:65535', sport => 137 },
	{ action => 'PVEFW-reject', proto => 'tcp', dport => '135,139,445', nbdport => 3 },
	{ action => 'DROP', proto => 'udp', dport => 1900 }, # UPnP
	# Drop new/NotSyn traffic so that it doesn't get logged
	"-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
	# Drop DNS replies
	{ action => 'DROP', proto => 'udp', sport => 53 },
    ],
    'PVEFW-tcpflags' => [
	# same as shorewall tcpflags action.
	# Packets arriving on this interface are checked for som illegal combinations of TCP flags
	"-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -g PVEFW-logflags",
	"-p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -g PVEFW-logflags",
	"-p tcp -m tcp --tcp-flags SYN,RST SYN,RST -g PVEFW-logflags",
	"-p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -g PVEFW-logflags",
	"-p tcp -m tcp --sport 0 --tcp-flags FIN,SYN,RST,ACK SYN -g PVEFW-logflags",
    ],
    'PVEFW-smurfs' => [
	# same as shorewall smurfs action
	# Filter packets for smurfs (packets with a broadcast address as the source).
	"-s 0.0.0.0/32 -j RETURN",
	"-m addrtype --src-type BROADCAST -g PVEFW-smurflog",
	"-s 224.0.0.0/4 -g PVEFW-smurflog",
    ],
};

# iptables -p icmp -h
my $icmp_type_names = {
    any => 1,
    'echo-reply' => 1,
    'destination-unreachable' => 1,
    'network-unreachable' => 1,
    'host-unreachable' => 1,
    'protocol-unreachable' => 1,
    'port-unreachable' => 1,
    'fragmentation-needed' => 1,
    'source-route-failed' => 1,
    'network-unknown' => 1,
    'host-unknown' => 1,
    'network-prohibited' => 1,
    'host-prohibited' => 1,
    'TOS-network-unreachable' => 1,
    'TOS-host-unreachable' => 1,
    'communication-prohibited' => 1,
    'host-precedence-violation' => 1,
    'precedence-cutoff' => 1,
    'source-quench' => 1,
    'redirect' => 1,
    'network-redirect' => 1,
    'host-redirect' => 1,
    'TOS-network-redirect' => 1,
    'TOS-host-redirect' => 1,
    'echo-request' => 1,
    'router-advertisement' => 1,
    'router-solicitation' => 1,
    'time-exceeded' => 1,
    'ttl-zero-during-transit' => 1,
    'ttl-zero-during-reassembly' => 1,
    'parameter-problem' => 1,
    'ip-header-bad' => 1,
    'required-option-missing' => 1,
    'timestamp-request' => 1,
    'timestamp-reply' => 1,
    'address-mask-request' => 1,
    'address-mask-reply' => 1,
};

sub init_firewall_macros {

    $pve_fw_parsed_macros = {};

    foreach my $k (keys %$pve_fw_macros) {
	my $lc_name = lc($k);
	my $macro = $pve_fw_macros->{$k};
	$pve_fw_preferred_macro_names->{$lc_name} = $k;
	$pve_fw_parsed_macros->{$k} = $macro;
    }
}

init_firewall_macros();

my $etc_services;

sub get_etc_services {

    return $etc_services if $etc_services;

    my $filename = "/etc/services";

    my $fh = IO::File->new($filename, O_RDONLY);
    if (!$fh) {
	warn "unable to read '$filename' - $!\n";
	return {};
    }

    my $services = {};

    while (my $line = <$fh>) {
	chomp ($line);
	next if $line =~m/^#/;
	next if ($line =~m/^\s*$/);

	if ($line =~ m!^(\S+)\s+(\S+)/(tcp|udp).*$!) {
	    $services->{byid}->{$2}->{name} = $1;
	    $services->{byid}->{$2}->{port} = $2;
	    $services->{byid}->{$2}->{$3} = 1;
	    $services->{byname}->{$1} = $services->{byid}->{$2};
	}
    }

    close($fh);

    $etc_services = $services;


    return $etc_services;
}

my $etc_protocols;

sub get_etc_protocols {
    return $etc_protocols if $etc_protocols;

    my $filename = "/etc/protocols";

    my $fh = IO::File->new($filename, O_RDONLY);
    if (!$fh) {
	warn "unable to read '$filename' - $!\n";
	return {};
    }

    my $protocols = {};

    while (my $line = <$fh>) {
	chomp ($line);
	next if $line =~m/^#/;
	next if ($line =~m/^\s*$/);

	if ($line =~ m!^(\S+)\s+(\d+)\s+.*$!) {
	    $protocols->{byid}->{$2}->{name} = $1;
	    $protocols->{byname}->{$1} = $protocols->{byid}->{$2};
	}
    }

    close($fh);

    $etc_protocols = $protocols;

    return $etc_protocols;
}

sub parse_address_list {
    my ($str) = @_;

    my $nbaor = 0;
    foreach my $aor (split(/,/, $str)) {
	if (!Net::IP->new($aor)) {
	    my $err = Net::IP::Error();
	    die "invalid IP address: $err\n";
	}else{
	    $nbaor++;
	}
    }
    return $nbaor;
}

sub parse_port_name_number_or_range {
    my ($str) = @_;

    my $services = PVE::Firewall::get_etc_services();
    my $nbports = 0;
    foreach my $item (split(/,/, $str)) {
	my $portlist = "";
	my $oldpon = undef;
	$nbports++;
	foreach my $pon (split(':', $item, 2)) {
	    $pon = $services->{byname}->{$pon}->{port} if $services->{byname}->{$pon}->{port};
	    if ($pon =~ m/^\d+$/){
		die "invalid port '$pon'\n" if $pon < 0 && $pon > 65535;
		die "port '$pon' must be bigger than port '$oldpon' \n" if $oldpon && ($pon < $oldpon);
		$oldpon = $pon;
	    }else{
		die "invalid port $services->{byname}->{$pon}\n" if !$services->{byname}->{$pon};
	    }
	}
    }

    return ($nbports);
}

PVE::JSONSchema::register_format('pve-fw-port-spec', \&pve_fw_verify_port_spec);
sub pve_fw_verify_port_spec {
   my ($portstr) = @_;

    parse_port_name_number_or_range($portstr);

   return $portstr;
}

PVE::JSONSchema::register_format('pve-fw-v4addr-spec', \&pve_fw_verify_v4addr_spec);
sub pve_fw_verify_v4addr_spec {
   my ($list) = @_;

   parse_address_list($list);

   return $list;
}

PVE::JSONSchema::register_format('pve-fw-protocol-spec', \&pve_fw_verify_protocol_spec);
sub pve_fw_verify_protocol_spec {
   my ($proto) = @_;

   my $protocols = get_etc_protocols();

   die "unknown protocol '$proto'\n" if $proto &&
       !(defined($protocols->{byname}->{$proto}) ||
	 defined($protocols->{byid}->{$proto}));

   return $proto;
}


# helper function for API

my $rule_properties = {
    pos => {
	description => "Update rule at position <pos>.",
	type => 'integer',
	minimum => 0,
	optional => 1,
    },
    digest => {
	type => 'string',
	optional => 1,
	maxLength => 27,
	minLength => 27,
    },
    type => {
	type => 'string',
	optional => 1,
	enum => ['in', 'out', 'group'],
    },
    action => {
	type => 'string',
	optional => 1,
	enum => ['ACCEPT', 'DROP', 'REJECT'],
    },
    macro => {
	type => 'string',
	optional => 1,
	maxLength => 128,
    },
    iface => get_standard_option('pve-iface', { optional => 1 }),
    source => {
	type => 'string', format => 'pve-fw-v4addr-spec',
	optional => 1,
    },
    dest => {
	type => 'string', format => 'pve-fw-v4addr-spec',
	optional => 1,
    },
    proto => {
	type => 'string', format => 'pve-fw-protocol-spec',
	optional => 1,
    },
    enable => {
	type => 'boolean',
	optional => 1,
    },
    sport => {
	type => 'string', format => 'pve-fw-port-spec',
	optional => 1,
    },
    dport => {
	type => 'string', format => 'pve-fw-port-spec',
	optional => 1,
    },
    comment => {
	type => 'string',
	optional => 1,
    },
};

sub cleanup_fw_rule {
    my ($rule, $digest, $pos) = @_;

    my $r = {};

    foreach my $k (keys %$rule) {
	next if !$rule_properties->{$k};
	my $v = $rule->{$k};
	next if !defined($v);
	$r->{$k} = $v;
	$r->{digest} = $digest;
	$r->{pos} = $pos;
    }

    return $r;
}

sub add_rule_properties {
    my ($properties) = @_;

    foreach my $k (keys %$rule_properties) {
	$properties->{$k} = $rule_properties->{$k};
    }
    
    return $properties;
}

sub copy_rule_data {
    my ($rule, $param) = @_;

    foreach my $k (keys %$rule_properties) {
	if (defined(my $v = $param->{$k})) {
	    if ($v eq '' || $v eq '-') {
		delete $rule->{$k};
	    } else {
		$rule->{$k} = $v;
	    }
	} else {
	    delete $rule->{$k};
	}
    }
    return $rule;
}

# core functions
my $bridge_firewall_enabled = 0;

sub enable_bridge_firewall {

    return if $bridge_firewall_enabled; # only once

    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/bridge/bridge-nf-call-iptables", "1");
    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "1");

    # make sure syncookies are enabled (which is default on newer 3.X kernels anyways)
    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/ipv4/tcp_syncookies", "1");

    $bridge_firewall_enabled = 1;
}

my $rule_format = "%-15s %-30s %-30s %-15s %-15s %-15s\n";

sub iptables_restore_cmdlist {
    my ($cmdlist) = @_;

    run_command("/sbin/iptables-restore -n", input => $cmdlist);
}

sub ipset_restore_cmdlist {
    my ($cmdlist) = @_;

    run_command("/usr/sbin/ipset restore", input => $cmdlist);
}

sub iptables_get_chains {

    my $res = {};

    # check what chains we want to track
    my $is_pvefw_chain = sub {
	my $name = shift;

	return 1 if $name =~ m/^PVEFW-\S+$/;

	return 1 if $name =~ m/^tap\d+i\d+-(:?IN|OUT)$/;

	return 1 if $name =~ m/^veth\d+.\d+-(:?IN|OUT)$/; # fixme: dev name is configurable

	return 1 if $name =~ m/^venet0-\d+-(:?IN|OUT)$/;

	return 1 if $name =~ m/^vmbr\d+-(:?FW|IN|OUT|IPS)$/;
	return 1 if $name =~ m/^GROUP-(:?[^\s\-]+)-(:?IN|OUT)$/;

	return undef;
    };

    my $table = '';

    my $hooks = {};

    my $parser = sub {
	my $line = shift;

	return if $line =~ m/^#/;
	return if $line =~ m/^\s*$/;

	if ($line =~ m/^\*(\S+)$/) {
	    $table = $1;
	    return;
	}

	return if $table ne 'filter';

	if ($line =~ m/^:(\S+)\s/) {
	    my $chain = $1;
	    return if !&$is_pvefw_chain($chain);
	    $res->{$chain} = "unknown";
	} elsif ($line =~ m/^-A\s+(\S+)\s.*--comment\s+\"PVESIG:(\S+)\"/) {
	    my ($chain, $sig) = ($1, $2);
	    return if !&$is_pvefw_chain($chain);
	    $res->{$chain} = $sig;
	} elsif ($line =~ m/^-A\s+(INPUT|OUTPUT|FORWARD)\s+-j\s+PVEFW-\1$/) {
	    $hooks->{$1} = 1;
	} else {
	    # simply ignore the rest
	    return;
	}
    };

    run_command("/sbin/iptables-save", outfunc => $parser);

    return wantarray ? ($res, $hooks) : $res;
}

sub iptables_chain_digest {
    my ($rules) = @_;
    my $digest = Digest::SHA->new('sha1');
    foreach my $rule (@$rules) { # order is important
	$digest->add($rule);
    }
    return $digest->b64digest;
}

sub ipset_chain_digest {
    my ($rules) = @_;

    my $digest = Digest::SHA->new('sha1');
    foreach my $rule (sort @$rules) { # note: sorted
	$digest->add($rule);
    }
    return $digest->b64digest;
}

sub ipset_get_chains {

    my $res = {};
    my $chains = {};

    my $parser = sub {
	my $line = shift;

	return if $line =~ m/^#/;
	return if $line =~ m/^\s*$/;
	if ($line =~ m/^(\S+)\s(\S+)\s(\S+)/) {
	    push @{$chains->{$2}}, $line;
	} else {
	    # simply ignore the rest
	    return;
	}
    };

    run_command("/usr/sbin/ipset save", outfunc => $parser);

    # compute digest for each chain
    foreach my $chain (keys %$chains) {
	$res->{$chain} = ipset_chain_digest($chains->{$chain});
    }

    return $res;
}

sub ruleset_generate_cmdstr {
    my ($ruleset, $chain, $rule, $actions, $goto) = @_;

    return if defined($rule->{enable}) && !$rule->{enable};

    die "unable to emit macro - internal error" if $rule->{macro}; # should not happen

    my $nbdport = defined($rule->{dport}) ? parse_port_name_number_or_range($rule->{dport}) : 0;
    my $nbsport = defined($rule->{sport}) ? parse_port_name_number_or_range($rule->{sport}) : 0;
    my $nbsource = $rule->{source} ? parse_address_list( $rule->{source}) : 0;
    my $nbdest = $rule->{dest} ? parse_address_list($rule->{dest}) : 0;

    my @cmd = ();

    push @cmd, "-i $rule->{iface_in}" if $rule->{iface_in};
    push @cmd, "-o $rule->{iface_out}" if $rule->{iface_out};

    push @cmd, "-m iprange --src-range" if $nbsource > 1;
    push @cmd, "-s $rule->{source}" if $rule->{source};
    push @cmd, "-m iprange --dst-range" if $nbdest > 1;
    push @cmd, "-d $rule->{dest}" if $rule->{dest};

    if ($rule->{proto}) {
	push @cmd, "-p $rule->{proto}";

	my $multiport = 0;
	$multiport++ if $nbdport > 1;
	$multiport++ if $nbsport > 1;

	push @cmd, "--match multiport" if $multiport;

	die "multiport: option '--sports' cannot be used together with '--dports'\n" 
	    if ($multiport == 2) && ($rule->{dport} ne $rule->{sport});

	if ($rule->{dport}) {
	    if ($rule->{proto} && $rule->{proto} eq 'icmp') {
		# Note: we use dport to store --icmp-type
		die "unknown icmp-type '$rule->{dport}'\n" if !defined($icmp_type_names->{$rule->{dport}});
		push @cmd, "-m icmp --icmp-type $rule->{dport}";
	    } else {
		if ($nbdport > 1) {
		    if ($multiport == 2) {
			push @cmd,  "--ports $rule->{dport}";
		    } else {
			push @cmd, "--dports $rule->{dport}";
		    }
		} else {
		    push @cmd, "--dport $rule->{dport}";
		}
	    }
	}

	if ($rule->{sport}) {
	    if ($nbsport > 1) {
		push @cmd, "--sports $rule->{sport}" if $multiport != 2;
	    } else {
		push @cmd, "--sport $rule->{sport}";
	    }
	}
    } elsif ($rule->{dport} || $rule->{sport}) {
	warn "ignoring destination port '$rule->{dport}' - no protocol specified\n" if $rule->{dport};
	warn "ignoring source port '$rule->{sport}' - no protocol specified\n" if $rule->{sport};
    }

    push @cmd, "-m addrtype --dst-type $rule->{dsttype}" if $rule->{dsttype};

    if (my $action = $rule->{action}) {
	$action = $actions->{$action} if defined($actions->{$action}); 
	$goto = 1 if !defined($goto) && $action eq 'PVEFW-SET-ACCEPT-MARK';
	push @cmd, $goto ? "-g $action" : "-j $action";
    }

    return scalar(@cmd) ? join(' ', @cmd) : undef;
}

my $apply_macro = sub {
    my ($macro_name, $param) = @_;

    my $macro_rules = $pve_fw_parsed_macros->{$macro_name};
    die "unknown macro '$macro_name'\n" if !$macro_rules; # should not happen

    my $rules = [];

    foreach my $templ (@$macro_rules) {
	my $rule = {};
	my $param_used = {};
	foreach my $k (keys %$templ) {
	    my $v = $templ->{$k};
	    if ($v eq 'PARAM') {
		$v = $param->{$k};
		$param_used->{$k} = 1;
	    } elsif ($v eq 'DEST') {
		$v = $param->{dest};
		$param_used->{dest} = 1;
	    } elsif ($v eq 'SOURCE') {
		$v = $param->{source};
		$param_used->{source} = 1;
	    }

	    die "missing parameter '$k' in macro '$macro_name'\n" if !defined($v);
	    $rule->{$k} = $v;
	}
	foreach my $k (keys %$param) {
	    next if $k eq 'macro';
	    next if !defined($param->{$k});
	    next if $param_used->{$k};
	    if (defined($rule->{$k})) {
		die "parameter '$k' already define in macro (value = '$rule->{$k}')\n"
		    if $rule->{$k} ne $param->{$k};
	    } else {
		$rule->{$k} = $param->{$k};
	    }
	}
	push @$rules, $rule;
    }

    return $rules;
};

sub ruleset_generate_rule {
    my ($ruleset, $chain, $rule, $actions, $goto) = @_;

    my $rules;

    if ($rule->{macro}) {
	$rules = &$apply_macro($rule->{macro}, $rule);
    } else {
	$rules = [ $rule ];
    }

    foreach my $tmp (@$rules) { 
	if (my $cmdstr = ruleset_generate_cmdstr($ruleset, $chain, $tmp, $actions, $goto)) {
	    ruleset_addrule($ruleset, $chain, $cmdstr);
	}
    }
}

sub ruleset_generate_rule_insert {
    my ($ruleset, $chain, $rule, $actions, $goto) = @_;

    die "implement me" if $rule->{macro}; # not implemented, because not needed so far

    if (my $cmdstr = ruleset_generate_cmdstr($ruleset, $chain, $rule, $actions, $goto)) {
	ruleset_insertrule($ruleset, $chain, $cmdstr);
    }
}

sub ruleset_create_chain {
    my ($ruleset, $chain) = @_;

    die "Invalid chain name '$chain' (28 char max)\n" if length($chain) > 28;
    die "chain name may not contain collons\n" if $chain =~ m/:/; # because of log format

    die "chain '$chain' already exists\n" if $ruleset->{$chain};

    $ruleset->{$chain} = [];
}

sub ruleset_chain_exist {
    my ($ruleset, $chain) = @_;

    return $ruleset->{$chain} ? 1 : undef;
}

sub ruleset_addrule {
   my ($ruleset, $chain, $rule) = @_;

   die "no such chain '$chain'\n" if !$ruleset->{$chain};

   push @{$ruleset->{$chain}}, "-A $chain $rule";
}

sub ruleset_insertrule {
   my ($ruleset, $chain, $rule) = @_;

   die "no such chain '$chain'\n" if !$ruleset->{$chain};

   unshift @{$ruleset->{$chain}}, "-A $chain $rule";
}

sub get_log_rule_base {
    my ($chain, $vmid, $msg, $loglevel) = @_;
    
    die "internal error - no log level" if !defined($loglevel);

    $vmid = 0 if !defined($vmid);

    # Note: we use special format for prefix to pass further 
    # info to log daemon (VMID, LOGVELEL and CHAIN)

    return "-j NFLOG --nflog-prefix \":$vmid:$loglevel:$chain: $msg\"";
}

sub ruleset_addlog {
    my ($ruleset, $chain, $vmid, $msg, $loglevel, $rule) = @_;

    return if !defined($loglevel);

    my $logrule = get_log_rule_base($chain, $vmid, $msg, $loglevel);

    $logrule = "$rule $logrule" if defined($rule);

    ruleset_addrule($ruleset, $chain, $logrule)
}

sub generate_bridge_chains {
    my ($ruleset, $hostfw_conf, $bridge, $routing_table) = @_;

    my $options = $hostfw_conf->{options} || {};

    die "error: detected direct route to bridge '$bridge'\n"
	if !$options->{allow_bridge_route} && $routing_table->{$bridge};

    if (!ruleset_chain_exist($ruleset, "$bridge-FW")) {
	ruleset_create_chain($ruleset, "$bridge-FW");
	ruleset_addrule($ruleset, "PVEFW-FORWARD", "-o $bridge -m physdev --physdev-is-out -j $bridge-FW");
	ruleset_addrule($ruleset, "PVEFW-FORWARD", "-i $bridge -m physdev --physdev-is-in -j $bridge-FW");
    }

    if (!ruleset_chain_exist($ruleset, "$bridge-OUT")) {
	ruleset_create_chain($ruleset, "$bridge-OUT");
	ruleset_addrule($ruleset, "$bridge-FW", "-m physdev --physdev-is-in -j $bridge-OUT");
	ruleset_insertrule($ruleset, "PVEFW-INPUT", "-i $bridge -m physdev --physdev-is-in -j $bridge-OUT");
    }

    if (!ruleset_chain_exist($ruleset, "$bridge-IN")) {
	ruleset_create_chain($ruleset, "$bridge-IN");
	ruleset_addrule($ruleset, "$bridge-FW", "-m physdev --physdev-is-out -j $bridge-IN");
	ruleset_addrule($ruleset, "$bridge-FW", "-m mark --mark 1 -j ACCEPT");
	# accept traffic to unmanaged bridge ports
	ruleset_addrule($ruleset, "$bridge-FW", "-m physdev --physdev-is-out -j ACCEPT ");
    }
}

sub ruleset_add_chain_policy {
    my ($ruleset, $chain, $vmid, $policy, $loglevel, $accept_action) = @_;

    if ($policy eq 'ACCEPT') {

	ruleset_generate_rule($ruleset, $chain, { action => 'ACCEPT' },
			      { ACCEPT =>  $accept_action});

    } elsif ($policy eq 'DROP') {

	ruleset_addrule($ruleset, $chain, "-j PVEFW-Drop");

	ruleset_addlog($ruleset, $chain, $vmid, "policy $policy: ", $loglevel);

	ruleset_addrule($ruleset, $chain, "-j DROP");
    } elsif ($policy eq 'REJECT') {
	ruleset_addrule($ruleset, $chain, "-j PVEFW-Reject");

	ruleset_addlog($ruleset, $chain, $vmid, "policy $policy: ", $loglevel);

	ruleset_addrule($ruleset, $chain, "-g PVEFW-reject");
    } else {
	# should not happen
	die "internal error: unknown policy '$policy'";
    }
}

sub ruleset_create_vm_chain {
    my ($ruleset, $chain, $options, $macaddr, $direction) = @_;

    ruleset_create_chain($ruleset, $chain);
    my $accept = generate_nfqueue($options);

    if (!(defined($options->{nosmurfs}) && $options->{nosmurfs} == 0)) {
	ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID,NEW -j PVEFW-smurfs");
    }

    if (!(defined($options->{dhcp}) && $options->{dhcp} == 0)) {
	if ($direction eq 'OUT') {
	    ruleset_generate_rule($ruleset, $chain, { action => 'PVEFW-SET-ACCEPT-MARK', 
						      proto => 'udp', sport => 68, dport => 67 });
	} else {
	    ruleset_generate_rule($ruleset, $chain, { action => 'ACCEPT', 
						      proto => 'udp', sport => 67, dport => 68 });
	}
    }

    if ($options->{tcpflags}) {
	ruleset_addrule($ruleset, $chain, "-p tcp -j PVEFW-tcpflags");
    }

    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID -j DROP");
    if($direction eq 'OUT'){
	ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED -g PVEFW-SET-ACCEPT-MARK");

    }else{
	ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j $accept");
    }
    if ($direction eq 'OUT') {
	if (defined($macaddr) && !(defined($options->{macfilter}) && $options->{macfilter} == 0)) {
	    ruleset_addrule($ruleset, $chain, "-m mac ! --mac-source $macaddr -j DROP");
	}
	ruleset_addrule($ruleset, $chain, "-j MARK --set-mark 0"); # clear mark
    }


}

sub ruleset_generate_vm_rules {
    my ($ruleset, $rules, $cluster_conf, $chain, $netid, $direction, $options) = @_;

    my $lc_direction = lc($direction);

    foreach my $rule (@$rules) {
	next if $rule->{iface} && $rule->{iface} ne $netid;
	next if !$rule->{enable};
	if ($rule->{type} eq 'group') {
	    my $group_chain = "GROUP-$rule->{action}-$direction"; 
	    if(!ruleset_chain_exist($ruleset, $group_chain)){
		generate_group_rules($ruleset, $cluster_conf, $rule->{action});
	    }
	    ruleset_addrule($ruleset, $chain, "-j $group_chain");
	    if ($direction eq 'OUT'){
		ruleset_addrule($ruleset, $chain, "-m mark --mark 1 -j RETURN");
	    }else{
		my $accept = generate_nfqueue($options);
		ruleset_addrule($ruleset, $chain, "-m mark --mark 1 -j $accept");
	    }

	} else {
	    next if $rule->{type} ne $lc_direction;
	    if ($direction eq 'OUT') {
		ruleset_generate_rule($ruleset, $chain, $rule, 
				      { ACCEPT => "PVEFW-SET-ACCEPT-MARK", REJECT => "PVEFW-reject" });
	    } else {
		my $accept = generate_nfqueue($options);
		ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => $accept , REJECT => "PVEFW-reject" });
	    }
	}
    }
}

sub generate_nfqueue {
    my ($options) = @_;

    my $action = "";
    if($options->{ips}){
	$action = "NFQUEUE";
	if($options->{ips_queues} && $options->{ips_queues} =~ m/^(\d+)(:(\d+))?$/) {
	    if(defined($3) && defined($1)) {
		$action .= " --queue-balance $1:$3";
	    }elsif (defined($1)) {
		$action .= " --queue-num $1";
	    }
	}
	$action .= " --queue-bypass";
    }else{
	$action = "ACCEPT";
    }

    return $action;
}

sub ruleset_generate_vm_ipsrules {
    my ($ruleset, $options, $direction, $iface, $bridge) = @_;

    if ($options->{ips} && $direction eq 'IN') {
	my $nfqueue = generate_nfqueue($options);

	if (!ruleset_chain_exist($ruleset, "$bridge-IPS")) {
	    ruleset_create_chain($ruleset, "PVEFW-IPS");
	}

	if (!ruleset_chain_exist($ruleset, "$bridge-IPS")) {
	    ruleset_create_chain($ruleset, "$bridge-IPS");
	    ruleset_insertrule($ruleset, "PVEFW-IPS", "-o $bridge -m physdev --physdev-is-out -j $bridge-IPS");
	}

        ruleset_addrule($ruleset, "$bridge-IPS", "-m physdev --physdev-out $iface --physdev-is-bridged -j $nfqueue");
    }
}

sub generate_venet_rules_direction {
    my ($ruleset, $cluster_conf, $vmfw_conf, $vmid, $ip, $direction) = @_;

    parse_address_list($ip); # make sure we have a valid $ip list

    my $lc_direction = lc($direction);

    my $rules = $vmfw_conf->{rules};

    my $options = $vmfw_conf->{options};
    my $loglevel = get_option_log_level($options, "log_level_${lc_direction}");

    my $chain = "venet0-$vmid-$direction";

    ruleset_create_vm_chain($ruleset, $chain, $options, undef, $direction);

    ruleset_generate_vm_rules($ruleset, $rules, $cluster_conf, $chain, 'venet', $direction);

    # implement policy
    my $policy;

    if ($direction eq 'OUT') {
	$policy = $options->{policy_out} || 'ACCEPT'; # allow everything by default
    } else {
	$policy = $options->{policy_in} || 'DROP'; # allow nothing by default
    }

    my $accept = generate_nfqueue($options);
    my $accept_action = $direction eq 'OUT' ? "PVEFW-SET-ACCEPT-MARK" : $accept;
    ruleset_add_chain_policy($ruleset, $chain, $vmid, $policy, $loglevel, $accept_action);

    # plug into FORWARD, INPUT and OUTPUT chain
    if ($direction eq 'OUT') {
	ruleset_generate_rule_insert($ruleset, "PVEFW-FORWARD", {
	    action => $chain,
	    source => $ip,
	    iface_in => 'venet0'});

	ruleset_generate_rule_insert($ruleset, "PVEFW-INPUT", {
	    action => $chain,
	    source => $ip,
	    iface_in => 'venet0'});
    } else {
	ruleset_generate_rule($ruleset, "PVEFW-FORWARD", {
	    action => $chain,
	    dest => $ip,
	    iface_out => 'venet0'});

	ruleset_generate_rule($ruleset, "PVEFW-OUTPUT", {
	    action => $chain,
	    dest => $ip,
	    iface_out => 'venet0'});
    }
}

sub generate_tap_rules_direction {
    my ($ruleset, $cluster_conf, $iface, $netid, $macaddr, $vmfw_conf, $vmid, $bridge, $direction) = @_;

    my $lc_direction = lc($direction);

    my $rules = $vmfw_conf->{rules};

    my $options = $vmfw_conf->{options};
    my $loglevel = get_option_log_level($options, "log_level_${lc_direction}");

    my $tapchain = "$iface-$direction";

    ruleset_create_vm_chain($ruleset, $tapchain, $options, $macaddr, $direction);

    ruleset_generate_vm_rules($ruleset, $rules, $cluster_conf, $tapchain, $netid, $direction, $options);

    ruleset_generate_vm_ipsrules($ruleset, $options, $direction, $iface, $bridge);

    # implement policy
    my $policy;

    if ($direction eq 'OUT') {
	$policy = $options->{policy_out} || 'ACCEPT'; # allow everything by default
    } else {
	$policy = $options->{policy_in} || 'DROP'; # allow nothing by default
    }

    my $accept = generate_nfqueue($options);
    my $accept_action = $direction eq 'OUT' ? "PVEFW-SET-ACCEPT-MARK" : $accept;
    ruleset_add_chain_policy($ruleset, $tapchain, $vmid, $policy, $loglevel, $accept_action);

    # plug the tap chain to bridge chain
    if ($direction eq 'IN') {
	ruleset_insertrule($ruleset, "$bridge-IN",
			   "-m physdev --physdev-is-bridged --physdev-out $iface -j $tapchain");
    } else {
	ruleset_insertrule($ruleset, "$bridge-OUT",
			   "-m physdev --physdev-in $iface -j $tapchain");
    }
}

sub enable_host_firewall {
    my ($ruleset, $hostfw_conf, $cluster_conf) = @_;

    # fixme: allow security groups

    my $options = $hostfw_conf->{options};
    my $rules = $hostfw_conf->{rules};

    # host inbound firewall
    my $chain = "PVEFW-HOST-IN";
    ruleset_create_chain($ruleset, $chain);

    my $loglevel = get_option_log_level($options, "log_level_in");

    if (!(defined($options->{nosmurfs}) && $options->{nosmurfs} == 0)) {
	ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID,NEW -j PVEFW-smurfs");
    }

    if ($options->{tcpflags}) {
	ruleset_addrule($ruleset, $chain, "-p tcp -j PVEFW-tcpflags");
    }

    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID -j DROP");
    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-i lo -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-m addrtype --dst-type MULTICAST -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m conntrack --ctstate NEW --dport 5404:5405 -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m udp --dport 9000 -j ACCEPT");  #corosync

    # we use RETURN because we need to check also tap rules
    my $accept_action = 'RETURN';

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'in';
	ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" });
    }

    # implement input policy
    my $policy = $options->{policy_in} || 'DROP'; # allow nothing by default
    ruleset_add_chain_policy($ruleset, $chain, 0, $policy, $loglevel, $accept_action);

    # host outbound firewall
    $chain = "PVEFW-HOST-OUT";
    ruleset_create_chain($ruleset, $chain);

    $loglevel = get_option_log_level($options, "log_level_out");

    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID -j DROP");
    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-o lo -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-m addrtype --dst-type MULTICAST -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m conntrack --ctstate NEW --dport 5404:5405 -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m udp --dport 9000 -j ACCEPT"); #corosync

    # we use RETURN because we may want to check other thigs later
    $accept_action = 'RETURN';

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'out';
	ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" });
    }

    # implement output policy
    $policy = $options->{policy_out} || 'ACCEPT'; # allow everything by default
    ruleset_add_chain_policy($ruleset, $chain, 0, $policy, $loglevel, $accept_action);

    ruleset_addrule($ruleset, "PVEFW-OUTPUT", "-j PVEFW-HOST-OUT");
    ruleset_addrule($ruleset, "PVEFW-INPUT", "-j PVEFW-HOST-IN");
}

sub generate_group_rules {
    my ($ruleset, $cluster_conf, $group) = @_;
    die "no such security group '$group'\n" if !$cluster_conf->{groups}->{$group};

    my $rules = $cluster_conf->{groups}->{$group};

    my $chain = "GROUP-${group}-IN";

    ruleset_create_chain($ruleset, $chain);
    ruleset_addrule($ruleset, $chain, "-j MARK --set-mark 0"); # clear mark

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'in';
	ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => "PVEFW-SET-ACCEPT-MARK", REJECT => "PVEFW-reject" });
    }

    $chain = "GROUP-${group}-OUT";

    ruleset_create_chain($ruleset, $chain);
    ruleset_addrule($ruleset, $chain, "-j MARK --set-mark 0"); # clear mark

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'out';
	# we use PVEFW-SET-ACCEPT-MARK (Instead of ACCEPT) because we need to
	# check also other tap rules later
	ruleset_generate_rule($ruleset, $chain, $rule, 
			      { ACCEPT => 'PVEFW-SET-ACCEPT-MARK', REJECT => "PVEFW-reject" });
    }
}

my $MAX_NETS = 32;
my $valid_netdev_names = {};
for (my $i = 0; $i < $MAX_NETS; $i++)  {
    $valid_netdev_names->{"net$i"} = 1;
}

sub parse_fw_rule {
    my ($line, $need_iface, $allow_groups) = @_;

    my ($type, $action, $iface, $source, $dest, $proto, $dport, $sport);

    # we can add single line comments to the end of the rule
    my $comment = decode('utf8', $1) if $line =~ s/#\s*(.*?)\s*$//;

    # we can disable a rule when prefixed with '|'
    my $enable = 1;

    $enable = 0 if $line =~ s/^\|//;

    my @data = split(/\s+/, $line);
    my $expected_elements = $need_iface ? 8 : 7;

    die "wrong number of rule elements\n" if scalar(@data) > $expected_elements;

    if ($need_iface) {
	($type, $action, $iface, $source, $dest, $proto, $dport, $sport) = @data
    } else {
	($type, $action, $source, $dest, $proto, $dport, $sport) =  @data;
    }

    die "incomplete rule\n" if ! ($type && $action);

    my $macro;

    $type = lc($type);

    if ($type eq  'in' || $type eq 'out') {
	if ($action =~ m/^(ACCEPT|DROP|REJECT)$/) {
	    # OK
	} elsif ($action =~ m/^(\S+)\((ACCEPT|DROP|REJECT)\)$/) {
	    $action = $2;
	    my $preferred_name = $pve_fw_preferred_macro_names->{lc($1)};
	    die "unknown macro '$1'\n" if !$preferred_name;
	    $macro = $preferred_name;
	} else {
	    die "unknown action '$action'\n";
	}
    } elsif ($type eq 'group') {
	die "wrong number of rule elements\n" if scalar(@data) != 3;
	die "groups disabled\n" if !$allow_groups;

	die "invalid characters in group name\n" if $action !~ m/^[A-Za-z0-9_\-]+$/;	
    } else {
	die "unknown rule type '$type'\n";
    }

    if ($need_iface) {
	$iface = undef if $iface && $iface eq '-';
    }

    $proto = undef if $proto && $proto eq '-';
    pve_fw_verify_protocol_spec($proto) if $proto;

    $source = undef if $source && $source eq '-';
    $dest = undef if $dest && $dest eq '-';

    $dport = undef if $dport && $dport eq '-';
    $sport = undef if $sport && $sport eq '-';

    parse_port_name_number_or_range($dport) if defined($dport);
    parse_port_name_number_or_range($sport) if defined($sport);
 
    parse_address_list($source) if $source;
    parse_address_list($dest) if $dest;

    return {
	type => $type,
	enable => $enable,
	comment => $comment,
	action => $action,
	macro => $macro,
	iface => $iface,
	source => $source,
	dest => $dest,
	proto => $proto,
	dport => $dport,
	sport => $sport,
    };
}

sub parse_vmfw_option {
    my ($line) = @_;

    my ($opt, $value);

    my $loglevels = "emerg|alert|crit|err|warning|notice|info|debug|nolog";

    if ($line =~ m/^(enable|dhcp|macfilter|nosmurfs|tcpflags|ips):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(log_level_in|log_level_out):\s*(($loglevels)\s*)?$/i) {
	$opt = lc($1);
	$value = $2 ? lc($3) : '';
    } elsif ($line =~ m/^(policy_(in|out)):\s*(ACCEPT|DROP|REJECT)\s*$/i) {
	$opt = lc($1);
	$value = uc($3);
    } elsif ($line =~ m/^(ips_queues):\s*((\d+)(:(\d+))?)\s*$/i) {
	$opt = lc($1);
	$value = $2;
    } else {
	chomp $line;
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub parse_hostfw_option {
    my ($line) = @_;

    my ($opt, $value);

    my $loglevels = "emerg|alert|crit|err|warning|notice|info|debug|nolog";

    if ($line =~ m/^(enable|dhcp|nosmurfs|tcpflags|allow_bridge_route|optimize):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(log_level_in|log_level_out|tcp_flags_log_level|smurf_log_level):\s*(($loglevels)\s*)?$/i) {
	$opt = lc($1);
	$value = $2 ? lc($3) : '';
    } elsif ($line =~ m/^(policy_(in|out)):\s*(ACCEPT|DROP|REJECT)\s*$/i) {
	$opt = lc($1);
	$value = uc($3);
    } elsif ($line =~ m/^(nf_conntrack_max):\s*(\d+)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } else {
	chomp $line;
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub parse_clusterfw_option {
    my ($line) = @_;

    my ($opt, $value);

    if ($line =~ m/^(enable):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } else {
	chomp $line;
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub parse_vm_fw_rules {
    my ($filename, $fh) = @_;

    my $res = { rules => [], options => {}};

    my $section;

    my $digest = Digest::SHA->new('sha1');

    while (defined(my $line = <$fh>)) {
	$digest->add($line);

	next if $line =~ m/^#/;
	next if $line =~ m/^\s*$/;

	my $linenr = $fh->input_line_number();
	my $prefix = "$filename (line $linenr)";

	if ($line =~ m/^\[(\S+)\]\s*$/i) {
	    $section = lc($1);
	    warn "$prefix: ignore unknown section '$section'\n" if !$res->{$section};
	    next;
	}
	if (!$section) {
	    warn "$prefix: skip line - no section";
	    next;
	}

	next if !$res->{$section}; # skip undefined section

	if ($section eq 'options') {
	    eval {
		my ($opt, $value) = parse_vmfw_option($line);
		$res->{options}->{$opt} = $value;
	    };
	    warn "$prefix: $@" if $@;
	    next;
	}

	my $rule;
	eval { $rule = parse_fw_rule($line, 1, 1); };
	if (my $err = $@) {
	    warn "$prefix: $err";
	    next;
	}

	push @{$res->{$section}}, $rule;
    }

    $res->{digest} = $digest->b64digest;

    return $res;
}

sub parse_host_fw_rules {
    my ($filename, $fh) = @_;

    my $res = { rules => [], options => {}};

    my $section;

    my $digest = Digest::SHA->new('sha1');

    while (defined(my $line = <$fh>)) {
	$digest->add($line);

	next if $line =~ m/^#/;
	next if $line =~ m/^\s*$/;

	my $linenr = $fh->input_line_number();
	my $prefix = "$filename (line $linenr)";

	if ($line =~ m/^\[(\S+)\]\s*$/i) {
	    $section = lc($1);
	    warn "$prefix: ignore unknown section '$section'\n" if !$res->{$section};
	    next;
	}
	if (!$section) {
	    warn "$prefix: skip line - no section";
	    next;
	}

	next if !$res->{$section}; # skip undefined section

	if ($section eq 'options') {
	    eval {
		my ($opt, $value) = parse_hostfw_option($line);
		$res->{options}->{$opt} = $value;
	    };
	    warn "$prefix: $@" if $@;
	    next;
	}

	my $rule;
	eval { $rule = parse_fw_rule($line, 1, 1); };
	if (my $err = $@) {
	    warn "$prefix: $err";
	    next;
	}
	
	push @{$res->{$section}}, $rule;
    }

    $res->{digest} = $digest->b64digest;

    return $res;
}

sub parse_cluster_fw_rules {
    my ($filename, $fh) = @_;

    my $section;
    my $group;

    my $res = { rules => [], options => {}, groups => {}, ipset => {} };

    my $digest = Digest::SHA->new('sha1');

    while (defined(my $line = <$fh>)) {
	$digest->add($line);

	next if $line =~ m/^#/;
	next if $line =~ m/^\s*$/;

	my $linenr = $fh->input_line_number();
	my $prefix = "$filename (line $linenr)";

	if ($line =~ m/^\[options\]$/i) {
	    $section = 'options';
	    next;
	}

	if ($line =~ m/^\[group\s+(\S+)\]\s*$/i) {
	    $section = 'groups';
	    $group = lc($1);
	    next;
	}

	if ($line =~ m/^\[rules\]$/i) {
	    $section = 'rules';
	    next;
	}
    
	if ($line =~ m/^\[netgroup\s+(\S+)\]\s*$/i) {
	    $section = 'ipset';
	    $group = lc($1);
	    next;
	}

	if (!$section) {
	    warn "$prefix: skip line - no section";
	    next;
	}

	if ($section eq 'options') {
	    eval {
		my ($opt, $value) = parse_clusterfw_option($line);
		$res->{options}->{$opt} = $value;
	    };
	    warn "$prefix: $@" if $@;
	} elsif ($section eq 'rules') {
	    my $rule;
	    eval { $rule = parse_fw_rule($line, 1, 1); };
	    if (my $err = $@) {
		warn "$prefix: $err";
		next;
	    }
	    push @{$res->{$section}}, $rule;
	} elsif ($section eq 'groups') {
	    my $rule;
	    eval { $rule = parse_fw_rule($line, 0, 0); };
	    if (my $err = $@) {
		warn "$prefix: $err";
		next;
	    }
	    push @{$res->{$section}->{$group}}, $rule;
	} elsif ($section eq 'ipset') {
	    chomp $line;
	    $line =~ m/^(\!)?(\s)?((\d+)\.(\d+)\.(\d+)\.(\d+)(\/(\d+))?)/;
	    my $nomatch = $1;
	    my $ip = $3;

	    if(!$ip){
		warn "$prefix: $line is not an valid ip address";
		next;
	    }
	    if (!Net::IP->new($ip)) {
		warn "$prefix: $line is not an valid ip address";
		next;
	    }
	    $ip .= " nomatch" if $nomatch;

	    push @{$res->{$section}->{$group}}, $ip;
	}
    }

    $res->{digest} = $digest->b64digest;
    return $res;
}

sub run_locked {
    my ($code, @param) = @_;

    my $timeout = 10;

    my $res = lock_file($pve_fw_lock_filename, $timeout, $code, @param);

    die $@ if $@;

    return $res;
}

sub read_local_vm_config {

    my $openvz = {};
    my $qemu = {};

    my $vmdata = { openvz => $openvz, qemu => $qemu };

    my $vmlist = PVE::Cluster::get_vmlist();
    return $vmdata if !$vmlist || !$vmlist->{ids};
    my $ids = $vmlist->{ids};

    foreach my $vmid (keys %$ids) {
	next if !$vmid; # skip VE0
	my $d = $ids->{$vmid};
	next if !$d->{node} || $d->{node} ne $nodename;
	next if !$d->{type};
	if ($d->{type} eq 'openvz') {
	    if ($have_pve_manager) {
		my $cfspath = PVE::OpenVZ::cfs_config_path($vmid);
		if (my $conf = PVE::Cluster::cfs_read_file($cfspath)) {
		    $openvz->{$vmid} = $conf;
		}
	    }
	} elsif ($d->{type} eq 'qemu') {
	    if ($have_qemu_server) {
		my $cfspath = PVE::QemuServer::cfs_config_path($vmid);
		if (my $conf = PVE::Cluster::cfs_read_file($cfspath)) {
		    $qemu->{$vmid} = $conf;
		}
	    }
	}
    }

    return $vmdata;
};

sub load_vmfw_conf {
    my ($vmid) = @_;

    my $vmfw_conf = {};

    my $filename = "/etc/pve/firewall/$vmid.fw";
    if (my $fh = IO::File->new($filename, O_RDONLY)) {
	$vmfw_conf = parse_vm_fw_rules($filename, $fh);
    }

    return $vmfw_conf;
}

sub read_vm_firewall_configs {
    my ($vmdata) = @_;
    my $vmfw_configs = {};

    foreach my $vmid (keys %{$vmdata->{qemu}}, keys %{$vmdata->{openvz}}) {
	my $vmfw_conf = load_vmfw_conf($vmid);
	next if !$vmfw_conf->{options}; # skip if file does not exists
	$vmfw_configs->{$vmid} = $vmfw_conf;
    }

    return $vmfw_configs;
}

sub get_option_log_level {
    my ($options, $k) = @_;

    my $v = $options->{$k};
    $v = $default_log_level if !defined($v);

    return undef if $v eq '' || $v eq 'nolog';

    $v = $log_level_hash->{$v} if defined($log_level_hash->{$v});

    return $v if ($v >= 0) && ($v <= 7);

    warn "unknown log level ($k = '$v')\n";

    return undef;
}

sub generate_std_chains {
    my ($ruleset, $options) = @_;
    
    my $loglevel = get_option_log_level($options, 'smurf_log_level');

    # same as shorewall smurflog.
    my $chain = 'PVEFW-smurflog';

    push @{$pve_std_chains->{$chain}}, get_log_rule_base($chain, 0, "DROP: ", $loglevel) if $loglevel;
    push @{$pve_std_chains->{$chain}}, "-j DROP";

    # same as shorewall logflags action.
    $loglevel = get_option_log_level($options, 'tcp_flags_log_level');
    $chain = 'PVEFW-logflags';
    # fixme: is this correctly logged by pvewf-logger? (ther is no --log-ip-options for NFLOG)
    push @{$pve_std_chains->{$chain}}, get_log_rule_base($chain, 0, "DROP: ", $loglevel) if $loglevel;
    push @{$pve_std_chains->{$chain}}, "-j DROP";

    foreach my $chain (keys %$pve_std_chains) {
	ruleset_create_chain($ruleset, $chain);
	foreach my $rule (@{$pve_std_chains->{$chain}}) {
	    if (ref($rule)) {
		ruleset_generate_rule($ruleset, $chain, $rule);
	    } else {
		ruleset_addrule($ruleset, $chain, $rule);
	    }
	}
    }
}

sub generate_ipset_chains {
    my ($ipset_ruleset, $fw_conf) = @_;

    foreach my $ipset (keys %{$fw_conf->{ipset}}) {
	generate_ipset($ipset_ruleset, $ipset, $fw_conf->{ipset}->{$ipset});
    }
}

sub generate_ipset {
    my ($ipset_ruleset, $name, $options) = @_;

    my $hashsize = scalar(@$options);
    if ($hashsize <= 64) {
	$hashsize = 64;
    } else {
	$hashsize = round_powerof2($hashsize);
    }

    push @{$ipset_ruleset->{$name}}, "create $name hash:net family inet hashsize $hashsize maxelem $hashsize";

    foreach my $ip (@$options) {
	push @{$ipset_ruleset->{$name}}, "add $name $ip";
    }
}

sub round_powerof2 {
    my ($int) = @_;

    $int--;
    $int |= $int >> $_ foreach (1,2,4,8,16);
    return ++$int;
}

sub save_pvefw_status {
    my ($status) = @_;

    die "unknown status '$status' - internal error"
	if $status !~ m/^(stopped|active)$/;

    mkdir dirname($pve_fw_status_filename);
    PVE::Tools::file_set_contents($pve_fw_status_filename, $status);
}

sub read_pvefw_status {

    my $status = 'unknown';

    return 'stopped' if ! -f $pve_fw_status_filename;

    eval {
	$status = PVE::Tools::file_get_contents($pve_fw_status_filename);
    };
    warn $@ if $@;

    return $status;
}

# fixme: move to pve-common PVE::ProcFSTools
sub read_proc_net_route {
    my $filename = "/proc/net/route";

    my $res = {};

    my $fh = IO::File->new ($filename, "r");
    return $res if !$fh;

    my $int_to_quad = sub {
	return join '.' => map { ($_[0] >> 8*(3-$_)) % 256 } (3, 2, 1, 0);
    };

    while (defined(my $line = <$fh>)) {
	next if $line =~/^Iface\s+Destination/; # skip head
	my ($iface, $dest, $gateway, $metric, $mask, $mtu) = (split(/\s+/, $line))[0,1,2,6,7,8];
	push @{$res->{$iface}}, {
	    dest => &$int_to_quad(hex($dest)),
	    gateway => &$int_to_quad(hex($gateway)),
	    mask => &$int_to_quad(hex($mask)),
	    metric => $metric,
	    mtu => $mtu,
	};
    }

    return $res;
}

sub load_clusterfw_conf {

    my $cluster_conf = {};
     if (my $fh = IO::File->new($clusterfw_conf_filename, O_RDONLY)) {
	$cluster_conf = parse_cluster_fw_rules($clusterfw_conf_filename, $fh);
    }

    return $cluster_conf;
}

my $rules_to_conf = sub {
    my ($rules, $need_iface) = @_;

    my $raw = '';

    foreach my $rule (@$rules) {
	if ($rule->{type} eq  'in' || $rule->{type} eq 'out') {
	    $raw .= '|' if defined($rule->{enable}) && !$rule->{enable};
	    $raw .= uc($rule->{type});
	    $raw .= " " . $rule->{action};
	    $raw .= " " . ($rule->{iface} || '-') if $need_iface;
	    $raw .= " " . ($rule->{source} || '-');
	    $raw .= " " . ($rule->{dest} || '-');
	    $raw .= " " . ($rule->{proto} || '-');
	    $raw .= " " . ($rule->{dport} || '-');
	    $raw .= " " . ($rule->{sport} || '-');
	    $raw .= " # " . encode('utf8', $rule->{comment}) 
		if $rule->{comment} && $rule->{comment} !~ m/^\s*$/;
	    $raw .= "\n";
	} else {
	    die "implement me '$rule->{type}'";
	}
    }

    return $raw;
};

sub save_clusterfw_conf {
    my ($cluster_conf) = @_;

    my $raw = '';

    my $options = $cluster_conf->{options};
    if (scalar(keys %$options)) {
	$raw .= "[OPTIONS]\n\n";
	foreach my $opt (keys %$options) {
	    $raw .= "$opt: $options->{$opt}\n";
	}
	$raw .= "\n";
    }

    # fixme: save ipset

    my $rules = $cluster_conf->{rules};
    if (scalar(@$rules)) {
	$raw .= "[RULES]\n\n";
	$raw .= &$rules_to_conf($rules, 1);
	$raw .= "\n";
    }

    foreach my $group (sort keys %{$cluster_conf->{groups}}) {
	my $rules = $cluster_conf->{groups}->{$group};
	$raw .= "[group $group]\n\n";
	$raw .= &$rules_to_conf($rules, 0);
	$raw .= "\n";
    }

    PVE::Tools::file_set_contents($clusterfw_conf_filename, $raw);
}

sub load_hostfw_conf {

    my $hostfw_conf = {};
    my $filename = "/etc/pve/local/host.fw";
    if (my $fh = IO::File->new($filename, O_RDONLY)) {
	$hostfw_conf = parse_host_fw_rules($filename, $fh);
    }
    return $hostfw_conf;
}

sub compile {
    my $vmdata = read_local_vm_config();
    my $vmfw_configs = read_vm_firewall_configs($vmdata);

    my $routing_table = read_proc_net_route();

    my $cluster_conf = load_clusterfw_conf();

    my $ipset_ruleset = {};
    generate_ipset_chains($ipset_ruleset, $cluster_conf);

    my $ruleset = {};

    ruleset_create_chain($ruleset, "PVEFW-INPUT");
    ruleset_create_chain($ruleset, "PVEFW-OUTPUT");

    ruleset_create_chain($ruleset, "PVEFW-FORWARD");

    my $hostfw_conf = load_hostfw_conf();
    my $hostfw_options = $hostfw_conf->{options} || {};

    generate_std_chains($ruleset, $hostfw_options);

    my $hostfw_enable = !(defined($hostfw_options->{enable}) && ($hostfw_options->{enable} == 0));

    enable_host_firewall($ruleset, $hostfw_conf, $cluster_conf) if $hostfw_enable;

    # generate firewall rules for QEMU VMs
    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	my $conf = $vmdata->{qemu}->{$vmid};
	my $vmfw_conf = $vmfw_configs->{$vmid};
	next if !$vmfw_conf;
	next if defined($vmfw_conf->{options}->{enable}) && ($vmfw_conf->{options}->{enable} == 0);

	foreach my $netid (keys %$conf) {
	    next if $netid !~ m/^net(\d+)$/;
	    my $net = PVE::QemuServer::parse_net($conf->{$netid});
	    next if !$net;
	    my $iface = "tap${vmid}i$1";

	    my $bridge = $net->{bridge};
	    next if !$bridge; # fixme: ?

	    $bridge .= "v$net->{tag}" if $net->{tag};

	    generate_bridge_chains($ruleset, $hostfw_conf, $bridge, $routing_table);

	    my $macaddr = $net->{macaddr};
	    generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr, 
					 $vmfw_conf, $vmid, $bridge, 'IN');
	    generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr, 
					 $vmfw_conf, $vmid, $bridge, 'OUT');
	}
    }

    # generate firewall rules for OpenVZ containers
    foreach my $vmid (keys %{$vmdata->{openvz}}) {
	my $conf = $vmdata->{openvz}->{$vmid};

	my $vmfw_conf = $vmfw_configs->{$vmid};
	next if !$vmfw_conf;
	next if defined($vmfw_conf->{options}->{enable}) && ($vmfw_conf->{options}->{enable} == 0);

	if ($conf->{ip_address} && $conf->{ip_address}->{value}) {
	    my $ip = $conf->{ip_address}->{value};
	    generate_venet_rules_direction($ruleset, $cluster_conf, $vmfw_conf, $vmid, $ip, 'IN');
	    generate_venet_rules_direction($ruleset, $cluster_conf, $vmfw_conf, $vmid, $ip, 'OUT');
	}

	if ($conf->{netif} && $conf->{netif}->{value}) {
	    my $netif = PVE::OpenVZ::parse_netif($conf->{netif}->{value});
	    foreach my $netid (keys %$netif) {
		my $d = $netif->{$netid};
		my $bridge = $d->{bridge};
		if (!$bridge) {
		    warn "no bridge device for CT $vmid iface '$netid'\n";
		    next; # fixme?
		}
		
		generate_bridge_chains($ruleset, $hostfw_conf, $bridge, $routing_table);

		my $macaddr = $d->{mac};
		my $iface = $d->{host_ifname};
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr, 
					     $vmfw_conf, $vmid, $bridge, 'IN');
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr, 
					     $vmfw_conf, $vmid, $bridge, 'OUT');
	    }
	}
    }

    if($hostfw_options->{optimize}){

	my $accept = ruleset_chain_exist($ruleset, "PVEFW-IPS") ? "PVEFW-IPS" : "ACCEPT";
	ruleset_insertrule($ruleset, "PVEFW-FORWARD", "-m conntrack --ctstate RELATED,ESTABLISHED -j $accept");
	ruleset_insertrule($ruleset, "PVEFW-FORWARD", "-m conntrack --ctstate INVALID -j DROP");
    }

    # fixme: what log level should we use here?
    my $loglevel = get_option_log_level($hostfw_options, "log_level_out");

    # fixme: should we really block inter-bridge traffic?

    # always allow traffic from containers?
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-i venet0 -j RETURN");

    # disable interbridge routing
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-o vmbr+ -j PVEFW-Drop"); 
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-i vmbr+ -j PVEFW-Drop");
    ruleset_addlog($ruleset, "PVEFW-FORWARD", 0, "DROP: ", $loglevel, "-o vmbr+");  
    ruleset_addlog($ruleset, "PVEFW-FORWARD", 0, "DROP: ", $loglevel, "-i vmbr+");  
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-o vmbr+ -j DROP");  
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-i vmbr+ -j DROP");

    return wantarray ? ($ruleset, $hostfw_conf, $ipset_ruleset) : $ruleset;
}

sub get_ruleset_status {
    my ($ruleset, $active_chains, $digest_fn, $verbose) = @_;

    my $statushash = {};

    foreach my $chain (sort keys %$ruleset) {
	my $sig = &$digest_fn($ruleset->{$chain});

	$statushash->{$chain}->{sig} = $sig;

	my $oldsig = $active_chains->{$chain};
	if (!defined($oldsig)) {
	    $statushash->{$chain}->{action} = 'create';
	} else {
	    if ($oldsig eq $sig) {
		$statushash->{$chain}->{action} = 'exists';
	    } else {
		$statushash->{$chain}->{action} = 'update';
	    }
	}
	print "$statushash->{$chain}->{action} $chain ($sig)\n" if $verbose;
	foreach my $cmd (@{$ruleset->{$chain}}) {
	    print "\t$cmd\n" if $verbose;
	}
    }

    foreach my $chain (sort keys %$active_chains) {
	if (!defined($ruleset->{$chain})) {
	    my $sig = $active_chains->{$chain};
	    $statushash->{$chain}->{action} = 'delete';
	    $statushash->{$chain}->{sig} = $sig;
	    print "delete $chain ($sig)\n" if $verbose;
	}
    }

    return $statushash;
}

sub print_sig_rule {
    my ($chain, $sig) = @_;

    # We just use this to store a SHA1 checksum used to detect changes
    return "-A $chain -m comment --comment \"PVESIG:$sig\"\n";
}

sub get_ruleset_cmdlist {
    my ($ruleset, $verbose) = @_;

    my $cmdlist = "*filter\n"; # we pass this to iptables-restore;
 
    my ($active_chains, $hooks) = iptables_get_chains();
    my $statushash = get_ruleset_status($ruleset, $active_chains, \&iptables_chain_digest, $verbose);

    # create missing chains first
    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;
	next if $stat->{action} ne 'create';

	$cmdlist .= ":$chain - [0:0]\n";
    }

    foreach my $h (qw(INPUT OUTPUT FORWARD)) {
	if (!$hooks->{$h}) {
	    $cmdlist .= "-A $h -j PVEFW-$h\n";
	}
    }

    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;

	if ($stat->{action} eq 'update' || $stat->{action} eq 'create') {
	    $cmdlist .= "-F $chain\n";
	    foreach my $cmd (@{$ruleset->{$chain}}) {
		$cmdlist .= "$cmd\n";
	    }
	    $cmdlist .= print_sig_rule($chain, $stat->{sig});
	} elsif ($stat->{action} eq 'delete') {
	    die "internal error"; # this should not happen
	} elsif ($stat->{action} eq 'exists') {
	    # do nothing
	} else {
	    die "internal error - unknown status '$stat->{action}'";
	}
    }

    foreach my $chain (keys %$statushash) {
	next if $statushash->{$chain}->{action} ne 'delete';
	$cmdlist .= "-F $chain\n";
    }
    foreach my $chain (keys %$statushash) {
	next if $statushash->{$chain}->{action} ne 'delete';
	next if $chain eq 'PVEFW-INPUT';
	next if $chain eq 'PVEFW-OUTPUT';
	next if $chain eq 'PVEFW-FORWARD';
	$cmdlist .= "-X $chain\n";
    }

    my $changes = $cmdlist ne "*filter\n" ? 1 : 0;

    $cmdlist .= "COMMIT\n";

    return wantarray ? ($cmdlist, $changes) : $cmdlist;
}

sub get_ipset_cmdlist {
    my ($ruleset, $verbose) = @_;

    my $cmdlist = "";

    my $delete_cmdlist = "";

    my $active_chains = ipset_get_chains();
    my $statushash = get_ruleset_status($ruleset, $active_chains, \&ipset_chain_digest, $verbose);

    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;

	if ($stat->{action} eq 'create') {
	    foreach my $cmd (@{$ruleset->{$chain}}) {
		$cmdlist .= "$cmd\n";
	    }
	}

	if ($stat->{action} eq 'update') {
	    my $chain_swap = $chain."_swap";
	    
	    foreach my $cmd (@{$ruleset->{$chain}}) {
		$cmd =~ s/$chain/$chain_swap/;
		$cmdlist .= "$cmd\n";
	    }
	    $cmdlist .= "swap $chain_swap $chain\n";
	    $cmdlist .= "flush $chain_swap\n";
	    $cmdlist .= "destroy $chain_swap\n";
	}

    }

    foreach my $chain (keys %$statushash) {
	next if $statushash->{$chain}->{action} ne 'delete';

	$delete_cmdlist .= "flush $chain\n";
	$delete_cmdlist .= "destroy $chain\n";
    }

    my $changes = ($cmdlist || $delete_cmdlist) ? 1 : 0;
    
    return ($cmdlist, $delete_cmdlist, $changes);
}

sub apply_ruleset {
    my ($ruleset, $hostfw_conf, $ipset_ruleset, $verbose) = @_;

    enable_bridge_firewall();

    update_nf_conntrack_max($hostfw_conf);

    my ($ipset_create_cmdlist, $ipset_delete_cmdlist) = get_ipset_cmdlist($ipset_ruleset, undef, $verbose);

    my $cmdlist = get_ruleset_cmdlist($ruleset, $verbose);

    print $ipset_create_cmdlist if $verbose;

    print $ipset_delete_cmdlist if $verbose;

    print $cmdlist if $verbose;

    ipset_restore_cmdlist($ipset_create_cmdlist);

    iptables_restore_cmdlist($cmdlist);

    ipset_restore_cmdlist($ipset_delete_cmdlist) if $ipset_delete_cmdlist;

    # test: re-read status and check if everything is up to date
    my $active_chains = iptables_get_chains();
    my $statushash = get_ruleset_status($ruleset, $active_chains, \&iptables_chain_digest, $verbose);

    my $errors;
    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	if ($stat->{action} ne 'exists') {
	    warn "unable to update chain '$chain'\n";
	    $errors = 1;
	}
    }

    die "unable to apply firewall changes\n" if $errors;
}

sub update_nf_conntrack_max {
    my ($hostfw_conf) = @_;

    my $max = 65536; # reasonable default

    my $options = $hostfw_conf->{options} || {};

    if (defined($options->{nf_conntrack_max}) && ($options->{nf_conntrack_max} > $max)) {
	$max = $options->{nf_conntrack_max};
	$max = int(($max+ 8191)/8192)*8192; # round to multiples of 8192
    }

    my $filename_nf_conntrack_max = "/proc/sys/net/nf_conntrack_max";
    my $filename_hashsize = "/sys/module/nf_conntrack/parameters/hashsize";

    my $current = int(PVE::Tools::file_read_firstline($filename_nf_conntrack_max) || $max);

    if ($current != $max) {
	my $hashsize = int($max/4);
	PVE::ProcFSTools::write_proc_entry($filename_hashsize, $hashsize);
	PVE::ProcFSTools::write_proc_entry($filename_nf_conntrack_max, $max);
    }
}

sub remove_pvefw_chains {

    my ($chash, $hooks) = iptables_get_chains();
    my $cmdlist = "*filter\n";

    foreach my $h (qw(INPUT OUTPUT FORWARD)) {
	if ($hooks->{$h}) {
	    $cmdlist .= "-D $h -j PVEFW-$h\n";
	}
    }
 
    foreach my $chain (keys %$chash) {
	$cmdlist .= "-F $chain\n";
    }

    foreach my $chain (keys %$chash) {
	$cmdlist .= "-X $chain\n";
    }
    $cmdlist .= "COMMIT\n";

    iptables_restore_cmdlist($cmdlist);
}

sub update {
    my ($start, $verbose) = @_;

    my $code = sub {
	my $status = read_pvefw_status();

	my ($ruleset, $hostfw_conf, $ipset_ruleset) = compile();

	if ($start || $status eq 'active') {

	    save_pvefw_status('active')	if ($status ne 'active');

	    apply_ruleset($ruleset, $hostfw_conf, $ipset_ruleset, $verbose);
	} else {
	    print "Firewall not active (status = $status)\n" if $verbose;
	}
    };

    run_locked($code);
}


1;
