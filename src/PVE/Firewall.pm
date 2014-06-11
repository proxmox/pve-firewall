package PVE::Firewall;

use warnings;
use strict;
use POSIX;
use Data::Dumper;
use Digest::SHA;
use PVE::INotify;
use PVE::Exception qw(raise raise_param_exc);
use PVE::JSONSchema qw(register_standard_option get_standard_option);
use PVE::Cluster;
use PVE::ProcFSTools;
use PVE::Tools qw($IPV4RE);
use File::Basename;
use File::Path;
use IO::File;
use Net::IP;
use PVE::Tools qw(run_command lock_file dir_glob_foreach);
use Encode;

my $hostfw_conf_filename = "/etc/pve/local/host.fw";
my $pvefw_conf_dir = "/etc/pve/firewall";
my $clusterfw_conf_filename = "$pvefw_conf_dir/cluster.fw";

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

my $security_group_name_pattern = '[A-Za-z][A-Za-z0-9\-\_]+';
my $ipset_name_pattern = '[A-Za-z][A-Za-z0-9\-\_]+';
my $ip_alias_pattern = '[A-Za-z][A-Za-z0-9\-\_]+';

my $max_alias_name_length = 64;
my $max_ipset_name_length = 64;
my $max_group_name_length = 20;

PVE::JSONSchema::register_format('IPv4orCIDR', \&pve_verify_ipv4_or_cidr);
sub pve_verify_ipv4_or_cidr {
    my ($cidr, $noerr) = @_;

    if ($cidr =~ m!^(?:$IPV4RE)(/(\d+))?$!) {
	return $cidr if Net::IP->new($cidr);
	return undef if $noerr;
	die Net::IP::Error() . "\n";
    }
    return undef if $noerr;
    die "value does not look like a valid IP address or CIDR network\n";
}

PVE::JSONSchema::register_format('IPv4orCIDRorAlias', \&pve_verify_ipv4_or_cidr_or_alias);
sub pve_verify_ipv4_or_cidr_or_alias {
    my ($cidr, $noerr) = @_;

    return if $cidr =~ m/^(?:$ip_alias_pattern)$/;

    if ($cidr =~ m!^(?:$IPV4RE)(/(\d+))?$!) {
	return $cidr if Net::IP->new($cidr);
	return undef if $noerr;
	die Net::IP::Error() . "\n";
    }
    return undef if $noerr;
    die "value does not look like a valid IP address or CIDR network\n";
}

PVE::JSONSchema::register_standard_option('ipset-name', {
    description => "IP set name.",
    type => 'string',
    pattern => $ipset_name_pattern,
    minLength => 2,
    maxLength => $max_ipset_name_length,
});

PVE::JSONSchema::register_standard_option('pve-fw-alias', {
    description => "Alias name.",
    type => 'string',
    pattern => $ip_alias_pattern,
    minLength => 2,
    maxLength => $max_alias_name_length,
});

PVE::JSONSchema::register_standard_option('pve-fw-loglevel' => {
    description => "Log level.",
    type => 'string',
    enum => ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug', 'nolog'],
    optional => 1,
});

PVE::JSONSchema::register_standard_option('pve-security-group-name', {
    description => "Security Group name.",
    type => 'string',
    pattern => $security_group_name_pattern,
    minLength => 2,
    maxLength => $max_group_name_length,
});

my $feature_ipset_nomatch = 0;
eval  {
    my (undef, undef, $release) = POSIX::uname();
    if ($release =~ m/^(\d+)\.(\d+)\.\d+-/) {
	my ($major, $minor) = ($1, $2);
	$feature_ipset_nomatch = 1 if ($major > 3) ||
	    ($major == 3 && $minor >= 7);
    }

};

use Data::Dumper;

my $nodename = PVE::INotify::nodename();

my $pve_fw_lock_filename = "/var/lock/pvefw.lck";

my $default_log_level = 'nolog'; # avoid logs by default

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
	"Amanda Backup",
	{ action => 'PARAM', proto => 'udp', dport => '10080' },
	{ action => 'PARAM', proto => 'tcp', dport => '10080' },
    ],
    'Auth' => [
	"Auth (identd) traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '113' },
    ],
    'BGP' => [
	"Border Gateway Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '179' },
    ],
    'BitTorrent' => [
	"BitTorrent traffic for BitTorrent 3.1 and earlier",
	{ action => 'PARAM', proto => 'tcp', dport => '6881:6889' },
	{ action => 'PARAM', proto => 'udp', dport => '6881' },
    ],
    'BitTorrent32' => [
	"BitTorrent traffic for BitTorrent 3.2 and later",
	{ action => 'PARAM', proto => 'tcp', dport => '6881:6999' },
	{ action => 'PARAM', proto => 'udp', dport => '6881' },
    ],
    'CVS' => [
	"Concurrent Versions System pserver traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '2401' },
    ],
    'Citrix' => [
	"Citrix/ICA traffic (ICA, ICA Browser, CGP)",
	{ action => 'PARAM', proto => 'tcp', dport => '1494' },
	{ action => 'PARAM', proto => 'udp', dport => '1604' },
	{ action => 'PARAM', proto => 'tcp', dport => '2598' },
    ],
    'DAAP' => [
	"Digital Audio Access Protocol traffic (iTunes, Rythmbox daemons)",
	{ action => 'PARAM', proto => 'tcp', dport => '3689' },
	{ action => 'PARAM', proto => 'udp', dport => '3689' },
    ],
    'DCC' => [
	"Distributed Checksum Clearinghouse spam filtering mechanism",
	{ action => 'PARAM', proto => 'tcp', dport => '6277' },
    ],
    'DHCPfwd' => [
	"Forwarded DHCP traffic",
	{ action => 'PARAM', proto => 'udp', dport => '67:68', sport => '67:68' },
    ],
    'DNS' => [
	"Domain Name System traffic (upd and tcp)",
	{ action => 'PARAM', proto => 'udp', dport => '53' },
	{ action => 'PARAM', proto => 'tcp', dport => '53' },
    ],
    'Distcc' => [
	"Distributed Compiler service",
	{ action => 'PARAM', proto => 'tcp', dport => '3632' },
    ],
    'FTP' => [
	"File Transfer Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '21' },
    ],
    'Finger' => [
	"Finger protocol (RFC 742)",
	{ action => 'PARAM', proto => 'tcp', dport => '79' },
    ],
    'GNUnet' => [
	"GNUnet secure peer-to-peer networking traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '2086' },
	{ action => 'PARAM', proto => 'udp', dport => '2086' },
	{ action => 'PARAM', proto => 'tcp', dport => '1080' },
	{ action => 'PARAM', proto => 'udp', dport => '1080' },
    ],
    'GRE' => [
	"Generic Routing Encapsulation tunneling protocol",
	{ action => 'PARAM', proto => '47' },
    ],
    'Git' => [
	"Git distributed revision control traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '9418' },
    ],
    'HKP' => [
	"OpenPGP HTTP keyserver protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '11371' },
    ],
    'HTTP' => [
	"Hypertext Transfer Protocol (WWW)",
	{ action => 'PARAM', proto => 'tcp', dport => '80' },
    ],
    'HTTPS' => [
	"Hypertext Transfer Protocol (WWW) over SSL",
	{ action => 'PARAM', proto => 'tcp', dport => '443' },
    ],
    'ICPV2' => [
	"Internet Cache Protocol V2 (Squid) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '3130' },
    ],
    'ICQ' => [
	"AOL Instant Messenger traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '5190' },
    ],
    'IMAP' => [
	"Internet Message Access Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '143' },
    ],
    'IMAPS' => [
	"Internet Message Access Protocol over SSL",
	{ action => 'PARAM', proto => 'tcp', dport => '993' },
    ],
    'IPIP' => [
	"IPIP capsulation traffic",
	{ action => 'PARAM', proto => '94' },
    ],
    'IPsec' => [
	"IPsec traffic",
	{ action => 'PARAM', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', proto => '50' },
    ],
    'IPsecah' => [
	"IPsec authentication (AH) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '500', sport => '500' },
	{ action => 'PARAM', proto => '51' },
    ],
    'IPsecnat' => [
	"IPsec traffic and Nat-Traversal",
	{ action => 'PARAM', proto => 'udp', dport => '500' },
	{ action => 'PARAM', proto => 'udp', dport => '4500' },
	{ action => 'PARAM', proto => '50' },
    ],
    'IRC' => [
	"Internet Relay Chat traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '6667' },
    ],
    'Jetdirect' => [
	"HP Jetdirect printing",
	{ action => 'PARAM', proto => 'tcp', dport => '9100' },
    ],
    'L2TP' => [
	"Layer 2 Tunneling Protocol traffic",
	{ action => 'PARAM', proto => 'udp', dport => '1701' },
    ],
    'LDAP' => [
	"Lightweight Directory Access Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '389' },
    ],
    'LDAPS' => [
	"Secure Lightweight Directory Access Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '636' },
    ],
    'MSNP' => [
	"Microsoft Notification Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '1863' },
    ],
    'MSSQL' => [
	"Microsoft SQL Server",
	{ action => 'PARAM', proto => 'tcp', dport => '1433' },
    ],
    'Mail' => [
	"Mail traffic (SMTP, SMTPS, Submission)",
	{ action => 'PARAM', proto => 'tcp', dport => '25' },
	{ action => 'PARAM', proto => 'tcp', dport => '465' },
	{ action => 'PARAM', proto => 'tcp', dport => '587' },
    ],
    'Munin' => [
	"Munin networked resource monitoring traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '4949' },
    ],
    'MySQL' => [
	"MySQL server",
	{ action => 'PARAM', proto => 'tcp', dport => '3306' },
    ],
    'NNTP' => [
	"NNTP traffic (Usenet).",
	{ action => 'PARAM', proto => 'tcp', dport => '119' },
    ],
    'NNTPS' => [
	"Encrypted NNTP traffic (Usenet)",
	{ action => 'PARAM', proto => 'tcp', dport => '563' },
    ],
    'NTP' => [
	"Network Time Protocol (ntpd)",
	{ action => 'PARAM', proto => 'udp', dport => '123' },
    ],
    'OSPF' => [
	"OSPF multicast traffic",
	{ action => 'PARAM', proto => '89' },
    ],
    'OpenVPN' => [
	"OpenVPN traffic",
	{ action => 'PARAM', proto => 'udp', dport => '1194' },
    ],
    'PCA' => [
	"Symantec PCAnywere (tm)",
	{ action => 'PARAM', proto => 'udp', dport => '5632' },
	{ action => 'PARAM', proto => 'tcp', dport => '5631' },
    ],
    'POP3' => [
	"POP3 traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '110' },
    ],
    'POP3S' => [
	"Encrypted POP3 traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '995' },
    ],
    'PPtP' => [
	"Point-to-Point Tunneling Protocol",
	{ action => 'PARAM', proto => '47' },
	{ action => 'PARAM', proto => 'tcp', dport => '1723' },
    ],
    'Ping' => [
	"ICMP echo request",
	{ action => 'PARAM', proto => 'icmp', dport => 'echo-request' },
    ],
    'PostgreSQL' => [
	"PostgreSQL server",
	{ action => 'PARAM', proto => 'tcp', dport => '5432' },
    ],
    'Printer' => [
	"Line Printer protocol printing",
	{ action => 'PARAM', proto => 'tcp', dport => '515' },
    ],
    'RDP' => [
	"Microsoft Remote Desktop Protocol traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '3389' },
    ],
    'RIP' => [
	"Routing Information Protocol (bidirectional)",
	{ action => 'PARAM', proto => 'udp', dport => '520' },
    ],
    'RNDC' => [
	"BIND remote management protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '953' },
    ],
    'Razor' => [
	"Razor Antispam System",
	{ action => 'ACCEPT', proto => 'tcp', dport => '2703' },
    ],
    'Rdate' => [
	"Remote time retrieval (rdate)",
	{ action => 'PARAM', proto => 'tcp', dport => '37' },
    ],
    'Rsync' => [
	"Rsync server",
	{ action => 'PARAM', proto => 'tcp', dport => '873' },
    ],
    'SANE' => [
	"SANE network scanning",
	{ action => 'PARAM', proto => 'tcp', dport => '6566' },
    ],
    'SMB' => [
	"Microsoft SMB traffic",
	{ action => 'PARAM', proto => 'udp', dport => '135,445' },
	{ action => 'PARAM', proto => 'udp', dport => '137:139' },
	{ action => 'PARAM', proto => 'udp', dport => '1024:65535', sport => '137' },
	{ action => 'PARAM', proto => 'tcp', dport => '135,139,445' },
    ],
    'SMBswat' => [
	"Samba Web Administration Tool",
	{ action => 'PARAM', proto => 'tcp', dport => '901' },
    ],
    'SMTP' => [
	"Simple Mail Transfer Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '25' },
    ],
    'SMTPS' => [
	"Encrypted Simple Mail Transfer Protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '465' },
    ],
    'SNMP' => [
	"Simple Network Management Protocol",
	{ action => 'PARAM', proto => 'udp', dport => '161:162' },
	{ action => 'PARAM', proto => 'tcp', dport => '161' },
    ],
    'SPAMD' => [
	"Spam Assassin SPAMD traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '783' },
    ],
    'SSH' => [
	"Secure shell traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '22' },
    ],
    'SVN' => [
	"Subversion server (svnserve)",
	{ action => 'PARAM', proto => 'tcp', dport => '3690' },
    ],
    'SixXS' => [
	"SixXS IPv6 Deployment and Tunnel Broker",
	{ action => 'PARAM', proto => 'tcp', dport => '3874' },
	{ action => 'PARAM', proto => 'udp', dport => '3740' },
	{ action => 'PARAM', proto => '41' },
	{ action => 'PARAM', proto => 'udp', dport => '5072,8374' },
    ],
    'Squid' => [
	"Squid web proxy traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '3128' },
    ],
    'Submission' => [
	"Mail message submission traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '587' },
    ],
    'Syslog' => [
	"Syslog protocol (RFC 5424) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '514' },
	{ action => 'PARAM', proto => 'tcp', dport => '514' },
    ],
    'TFTP' => [
	"Trivial File Transfer Protocol traffic",
	{ action => 'PARAM', proto => 'udp', dport => '69' },
    ],
    'Telnet' => [
	"Telnet traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '23' },
    ],
    'Telnets' => [
	"Telnet over SSL",
	{ action => 'PARAM', proto => 'tcp', dport => '992' },
    ],
    'Time' => [
	"RFC 868 Time protocol",
	{ action => 'PARAM', proto => 'tcp', dport => '37' },
    ],
    'Trcrt' => [
	"Traceroute (for up to 30 hops) traffic",
	{ action => 'PARAM', proto => 'udp', dport => '33434:33524' },
	{ action => 'PARAM', proto => 'icmp', dport => 'echo-request' },
    ],
    'VNC' => [
	"VNC traffic for VNC display's 0 - 99",
	{ action => 'PARAM', proto => 'tcp', dport => '5900:5999' },
    ],
    'VNCL' => [
	"VNC traffic from Vncservers to Vncviewers in listen mode",
	{ action => 'PARAM', proto => 'tcp', dport => '5500' },
    ],
    'Web' => [
	"WWW traffic (HTTP and HTTPS)",
	{ action => 'PARAM', proto => 'tcp', dport => '80' },
	{ action => 'PARAM', proto => 'tcp', dport => '443' },
    ],
    'Webcache' => [
	"Web Cache/Proxy traffic (port 8080)",
	{ action => 'PARAM', proto => 'tcp', dport => '8080' },
    ],
    'Webmin' => [
	"Webmin traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '10000' },
    ],
    'Whois' => [
	"Whois (nicname, RFC 3912) traffic",
	{ action => 'PARAM', proto => 'tcp', dport => '43' },
    ],
};

my $pve_fw_parsed_macros;
my $pve_fw_macro_descr;
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
	if (!ref($macro->[0])) {
	    $pve_fw_macro_descr->{$k} = shift @$macro;
	}
	$pve_fw_preferred_macro_names->{$lc_name} = $k;
	$pve_fw_parsed_macros->{$k} = $macro;
    }
}

init_firewall_macros();

sub get_macros {
    return wantarray ? ($pve_fw_parsed_macros, $pve_fw_macro_descr): $pve_fw_parsed_macros;
}

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

my $ipv4_mask_hash_localnet = {
    '255.255.0.0' => 16,
    '255.255.128.0' => 17,
    '255.255.192.0' => 18,
    '255.255.224.0' => 19,
    '255.255.240.0' => 20,
    '255.255.248.0' => 21,
    '255.255.252.0' => 22,
    '255.255.254.0' => 23,
    '255.255.255.0' => 24,
    '255.255.255.128' => 25,
    '255.255.255.192' => 26,
    '255.255.255.224' => 27,
    '255.255.255.240' => 28,
    '255.255.255.248' => 29,
    '255.255.255.252' => 30,
};

my $__local_network;

sub local_network {
    my ($new_value) = @_;

    $__local_network = $new_value if defined($new_value);

    return $__local_network if defined($__local_network);

    eval {
	my $nodename = PVE::INotify::nodename();

	my $ip = PVE::Cluster::remote_node_ip($nodename);

	my $testip = Net::IP->new($ip);

	my $routes = PVE::ProcFSTools::read_proc_net_route();
	foreach my $entry (@$routes) {
	    my $mask = $ipv4_mask_hash_localnet->{$entry->{mask}};
	    next if !defined($mask);
	    return if $mask eq '0.0.0.0';
	    my $cidr = "$entry->{dest}/$mask";
	    my $testnet = Net::IP->new($cidr);
	    if ($testnet->overlaps($testip)) {
		$__local_network = $cidr;
		return;
	    }
	}
    };
    warn $@ if $@;

    return $__local_network;
}

my $max_iptables_ipset_name_length = 27;

sub compute_ipset_chain_name {
    my ($vmid, $ipset_name) = @_;

    $vmid = 0 if !defined($vmid);

    my $id = "$vmid-${ipset_name}";

   
    if ((length($id) + 6) > $max_iptables_ipset_name_length) {
	$id = PVE::Tools::fnv31a_hex($id);
    }

    return "PVEFW-$id";
}

sub parse_address_list {
    my ($str) = @_;

    if ($str =~ m/^(\+)(\S+)$/) { # ipset ref
	die "ipset name too long\n" if length($str) > ($max_ipset_name_length + 1);
	return;
    }

    if ($str =~ m/^${ip_alias_pattern}$/) {
	die "alias name too long\n" if length($str) > $max_alias_name_length;
	return;
    }

    my $count = 0;
    my $iprange = 0;
    foreach my $elem (split(/,/, $str)) {
	$count++;
	if (!Net::IP->new($elem)) {
	    my $err = Net::IP::Error();
	    die "invalid IP address: $err\n";
	}
	$iprange = 1 if $elem =~ m/-/;
    }

    die "you can use a range in a list\n" if $iprange && $count > 1;
}

sub parse_port_name_number_or_range {
    my ($str) = @_;

    my $services = PVE::Firewall::get_etc_services();
    my $count = 0;
    my $icmp_port = 0;

    foreach my $item (split(/,/, $str)) {
	$count++;
	if ($item =~ m/^(\d+):(\d+)$/) {
	    my ($port1, $port2) = ($1, $2);
	    die "invalid port '$port1'\n" if $port1 > 65535;
	    die "invalid port '$port2'\n" if $port2 > 65535;
	} elsif ($item =~ m/^(\d+)$/) {
	    my $port = $1;
	    die "invalid port '$port'\n" if $port > 65535;
	} else {
	    if ($icmp_type_names->{$item}) {
		$icmp_port = 1;
	    } else {
		die "invalid port '$item'\n" if !$services->{byname}->{$item};
	    }
	}
    }

    die "ICPM ports not allowed in port range\n" if $icmp_port && $count > 1;

    return $count;
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

sub copy_opject_with_digest {
    my ($object) = @_;

    my $sha = Digest::SHA->new('sha1');

    my $res = {};
    foreach my $k (sort keys %$object) {
	my $v = $object->{$k};
	next if !defined($v);
	$res->{$k} = $v;
	$sha->add($k, ':', $v, "\n");
    }

    my $digest = $sha->hexdigest;

    $res->{digest} = $digest;

    return wantarray ? ($res, $digest) : $res;
}

sub copy_list_with_digest {
    my ($list) = @_;

    my $sha = Digest::SHA->new('sha1');

    my $res = [];
    foreach my $entry (@$list) {
	my $data = {};
	foreach my $k (sort keys %$entry) {
	    my $v = $entry->{$k};
	    next if !defined($v);
	    $data->{$k} = $v;
	    # Note: digest ignores refs ($rule->{errors})
	    $sha->add($k, ':', $v, "\n") if !ref($v); ;
	}
	push @$res, $data;
    }

    my $digest = $sha->hexdigest;

    foreach my $entry (@$res) {
	$entry->{digest} = $digest;
    }

    return wantarray ? ($res, $digest) : $res;
}

my $rule_properties = {
    pos => {
	description => "Update rule at position <pos>.",
	type => 'integer',
	minimum => 0,
	optional => 1,
    },
    digest => get_standard_option('pve-config-digest'),
    type => {
	type => 'string',
	optional => 1,
	enum => ['in', 'out', 'group'],
    },
    action => {
	description => "Rule action ('ACCEPT', 'DROP', 'REJECT') or security group name.",
	type => 'string',
	optional => 1,
	pattern => $security_group_name_pattern,
	maxLength => 20,
	minLength => 2,
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

sub add_rule_properties {
    my ($properties) = @_;

    foreach my $k (keys %$rule_properties) {
	my $h = $rule_properties->{$k};
	# copy data, so that we can modify later without side effects
	foreach my $opt (keys %$h) { $properties->{$k}->{$opt} = $h->{$opt}; }
    }

    return $properties;
}

sub delete_rule_properties {
    my ($rule, $delete_str) = @_;

    foreach my $opt (PVE::Tools::split_list($delete_str)) {
	raise_param_exc({ 'delete' => "no such property ('$opt')"})
	    if !defined($rule_properties->{$opt});
	raise_param_exc({ 'delete' => "unable to delete required property '$opt'"})
	    if $opt eq 'type' || $opt eq 'action';
	delete $rule->{$opt};
    }

    return $rule;
}

my $apply_macro = sub {
    my ($macro_name, $param, $verify) = @_;

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

	    if (!defined($v)) {
		my $msg = "missing parameter '$k' in macro '$macro_name'";
		raise_param_exc({ macro => $msg }) if $verify;
		die "$msg\n";
	    }
	    $rule->{$k} = $v;
	}
	foreach my $k (keys %$param) {
	    next if $k eq 'macro';
	    next if !defined($param->{$k});
	    next if $param_used->{$k};
	    if (defined($rule->{$k})) {
		if ($rule->{$k} ne $param->{$k}) {
		    my $msg = "parameter '$k' already define in macro (value = '$rule->{$k}')";
		    raise_param_exc({ $k => $msg }) if $verify;
		    die "$msg\n";
		}
	    } else {
		$rule->{$k} = $param->{$k};
	    }
	}
	push @$rules, $rule;
    }

    return $rules;
};

my $rule_env_iface_lookup = {
    'ct' => 1,
    'vm' => 1,
    'group' => 0,
    'cluster' => 1,
    'host' => 1,
};

sub verify_rule {
    my ($rule, $cluster_conf, $fw_conf, $rule_env, $noerr) = @_;

    my $allow_groups = $rule_env eq 'group' ? 0 : 1;

    my $allow_iface = $rule_env_iface_lookup->{$rule_env};
    die "unknown rule_env '$rule_env'\n" if !defined($allow_iface); # should not happen

    my $errors = $rule->{errors} || {};

    my $error_count = 0;

    my $add_error = sub {
	my ($param, $msg)  = @_;
	chomp $msg;
	raise_param_exc({ $param => $msg }) if !$noerr;
	$error_count++;
	$errors->{$param} = $msg if !$errors->{$param};
    };

    my $check_ipset_or_alias_property = sub {
	my ($name) = @_;

	if (my $value = $rule->{$name}) {
	    if ($value =~ m/^\+/) {
		if ($value =~ m/^\+(${ipset_name_pattern})$/) {
		    &$add_error($name, "no such ipset '$1'")
			if !($cluster_conf->{ipset}->{$1} || ($fw_conf && $fw_conf->{ipset}->{$1}));

		} else {
		    &$add_error($name, "invalid ipset name '$value'");
		}
	    } elsif ($value =~ m/^${ip_alias_pattern}$/){
		my $alias = lc($value);
		&$add_error($name, "no such alias '$value'")
		    if !($cluster_conf->{aliases}->{$alias} || ($fw_conf && $fw_conf->{aliases}->{$alias}))
	    }
	}
    };

    my $type = $rule->{type};
    my $action = $rule->{action};

    &$add_error('type', "missing property") if !$type;
    &$add_error('action', "missing property") if !$action;

    if ($type) {
	if ($type eq  'in' || $type eq 'out') {
	    &$add_error('action', "unknown action '$action'")
		if $action && ($action !~ m/^(ACCEPT|DROP|REJECT)$/);
	} elsif ($type eq 'group') {
	    &$add_error('type', "security groups not allowed")
		if !$allow_groups;
	    &$add_error('action', "invalid characters in security group name")
		if $action && ($action !~ m/^${security_group_name_pattern}$/);
	} else {
	    &$add_error('type', "unknown rule type '$type'");
	}
    }

    if ($rule->{iface}) {
	&$add_error('type', "parameter -i not allowed for this rule type")
	    if !$allow_iface;
	eval { PVE::JSONSchema::pve_verify_iface($rule->{iface}); };
	&$add_error('iface', $@) if $@;
    	if ($rule_env eq 'vm') {
	    &$add_error('iface', "value does not match the regex pattern 'net\\d+'")
		if $rule->{iface} !~  m/^net(\d+)$/;
	} elsif ($rule_env eq 'ct') {
	    &$add_error('iface', "value does not match the regex pattern '(venet|eth\\d+)'")
		if $rule->{iface} !~  m/^(venet|eth(\d+))$/;
	}
    }

    if ($rule->{macro}) {
	if (my $preferred_name = $pve_fw_preferred_macro_names->{lc($rule->{macro})}) {
	    $rule->{macro} = $preferred_name;
	} else {
	    &$add_error('macro', "unknown macro '$rule->{macro}'");
	}
    }

    if ($rule->{proto}) {
	eval { pve_fw_verify_protocol_spec($rule->{proto}); };
	&$add_error('proto', $@) if $@;
    }

    if ($rule->{dport}) {
	eval { parse_port_name_number_or_range($rule->{dport}); };
	&$add_error('dport', $@) if $@;
	&$add_error('proto', "missing property - 'dport' requires this property")
	    if !$rule->{proto};
    }

    if ($rule->{sport}) {
	eval { parse_port_name_number_or_range($rule->{sport}); };
	&$add_error('sport', $@) if $@;
	&$add_error('proto', "missing property - 'sport' requires this property")
	    if !$rule->{proto};
    }

    if ($rule->{source}) {
	eval { parse_address_list($rule->{source}); };
	&$add_error('source', $@) if $@;
	&$check_ipset_or_alias_property('source');
    }

    if ($rule->{dest}) {
	eval { parse_address_list($rule->{dest}); };
	&$add_error('dest', $@) if $@;
	&$check_ipset_or_alias_property('dest');
    }

    if ($rule->{macro} && !$error_count) {
	eval { &$apply_macro($rule->{macro}, $rule, 1); };
	if (my $err = $@) {
	    if (ref($err) eq "PVE::Exception" && $err->{errors}) {
		my $eh = $err->{errors};
		foreach my $p (keys %$eh) {
		    &$add_error($p, $eh->{$p});
		}
	    } else {
		&$add_error('macro', "$err");
	    }
	}
    }

    $rule->{errors} = $errors if $error_count;

    return $rule;
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

	return 1 if $name =~ m/^fwbr\d+(v\d+)?-(:?FW|IN|OUT|IPS)$/;
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
	if ($line =~ m/^(?:\S+)\s(PVEFW-\S+)\s(?:\S+).*/) {
	    my $chain = $1;
	    $line =~ s/\s+$//; # delete trailing white space
	    push @{$chains->{$chain}}, $line;
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
    my ($ruleset, $chain, $rule, $actions, $goto, $cluster_conf, $fw_conf) = @_;

    return if defined($rule->{enable}) && !$rule->{enable};
    return if $rule->{errors};

    die "unable to emit macro - internal error" if $rule->{macro}; # should not happen

    my $nbdport = defined($rule->{dport}) ? parse_port_name_number_or_range($rule->{dport}) : 0;
    my $nbsport = defined($rule->{sport}) ? parse_port_name_number_or_range($rule->{sport}) : 0;

    my @cmd = ();

    push @cmd, "-i $rule->{iface_in}" if $rule->{iface_in};
    push @cmd, "-o $rule->{iface_out}" if $rule->{iface_out};

    my $source = $rule->{source};
    my $dest = $rule->{dest};

    if ($source) {
        if ($source =~ m/^\+/) {
	    if ($source =~ m/^\+(${ipset_name_pattern})$/) {
		my $name = $1;
		if ($fw_conf && $fw_conf->{ipset}->{$name}) {
		    my $ipset_chain = compute_ipset_chain_name($fw_conf->{vmid}, $name);
		    push @cmd, "-m set --match-set ${ipset_chain} src";
		} elsif ($cluster_conf && $cluster_conf->{ipset}->{$name}) {
		    my $ipset_chain = compute_ipset_chain_name(0, $name);
		    push @cmd, "-m set --match-set ${ipset_chain} src";
		} else {
		    die "no such ipset '$name'\n";
		}
	    } else {
		die "invalid security group name '$source'\n";
	    }
	} elsif ($source =~ m/^${ip_alias_pattern}$/){
	    my $alias = lc($source);
	    my $e = $fw_conf->{aliases}->{$alias} if $fw_conf;
	    $e = $cluster_conf->{aliases}->{$alias} if !$e && $cluster_conf;
	    die "no such alias '$source'\n" if !$e;
	    push @cmd, "-s $e->{cidr}";
        } elsif ($source =~ m/\-/){
	    push @cmd, "-m iprange --src-range $source";
	} else {
	    push @cmd, "-s $source";
        }
    }

    if ($dest) {
        if ($dest =~ m/^\+/) {
	    if ($dest =~ m/^\+(${ipset_name_pattern})$/) {
		my $name = $1;
		if ($fw_conf && $fw_conf->{ipset}->{$name}) {
		    my $ipset_chain = compute_ipset_chain_name($fw_conf->{vmid}, $name);
		    push @cmd, "-m set --match-set ${ipset_chain} dst";
		} elsif ($cluster_conf && $cluster_conf->{ipset}->{$name}) {
		    my $ipset_chain = compute_ipset_chain_name(0, $name);
		    push @cmd, "-m set --match-set ${ipset_chain} dst";
		} else {
		    die "no such ipset '$name'\n";
		}
	    } else {
		die "invalid security group name '$dest'\n";
	    }
	} elsif ($dest =~ m/^${ip_alias_pattern}$/){
	    my $alias = lc($dest);
	    my $e = $fw_conf->{aliases}->{$alias} if $fw_conf;
	    $e = $cluster_conf->{aliases}->{$alias} if !$e && $cluster_conf;
	    die "no such alias '$dest'\n" if !$e;
	    push @cmd, "-d $e->{cidr}";
        } elsif ($dest =~ m/^(\d+)\.(\d+).(\d+).(\d+)\-(\d+)\.(\d+).(\d+).(\d+)$/){
	    push @cmd, "-m iprange --dst-range $dest";
	} else {
	    push @cmd, "-d $dest";
        }
    }

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
	die "destination port '$rule->{dport}', but no protocol specified\n" if $rule->{dport};
	die "source port '$rule->{sport}', but no protocol specified\n" if $rule->{sport};
    }

    push @cmd, "-m addrtype --dst-type $rule->{dsttype}" if $rule->{dsttype};

    if (my $action = $rule->{action}) {
	$action = $actions->{$action} if defined($actions->{$action});
	$goto = 1 if !defined($goto) && $action eq 'PVEFW-SET-ACCEPT-MARK';
	push @cmd, $goto ? "-g $action" : "-j $action";
    }

    return scalar(@cmd) ? join(' ', @cmd) : undef;
}

sub ruleset_generate_rule {
    my ($ruleset, $chain, $rule, $actions, $goto, $cluster_conf, $fw_conf) = @_;

    my $rules;

    if ($rule->{macro}) {
	$rules = &$apply_macro($rule->{macro}, $rule);
    } else {
	$rules = [ $rule ];
    }

    # update all or nothing

    my @cmds = ();
    foreach my $tmp (@$rules) {
	if (my $cmdstr = ruleset_generate_cmdstr($ruleset, $chain, $tmp, $actions, $goto, $cluster_conf, $fw_conf)) {
	    push @cmds, $cmdstr;
	}
    }

    foreach my $cmdstr (@cmds) {
	ruleset_addrule($ruleset, $chain, $cmdstr);
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

    ruleset_addrule($ruleset, $chain, $logrule);
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

sub ruleset_chain_add_conn_filters {
    my ($ruleset, $chain, $accept) = @_;

    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID -j DROP");
    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j $accept");
}

sub ruleset_chain_add_input_filters {
    my ($ruleset, $chain, $options, $cluster_conf, $loglevel) = @_;

    if ($cluster_conf->{ipset}->{blacklist}){
	if (!ruleset_chain_exist($ruleset, "PVEFW-blacklist")) {
	    ruleset_create_chain($ruleset, "PVEFW-blacklist");
	    ruleset_addlog($ruleset, "PVEFW-blacklist", 0, "DROP: ", $loglevel) if $loglevel;
	    ruleset_addrule($ruleset, "PVEFW-blacklist", "-j DROP");
	}
	my $ipset_chain = compute_ipset_chain_name(0, 'blacklist');
	ruleset_addrule($ruleset, $chain, "-m set --match-set ${ipset_chain} src -j PVEFW-blacklist");
    }

    if (!(defined($options->{nosmurfs}) && $options->{nosmurfs} == 0)) {
	ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID,NEW -j PVEFW-smurfs");
    }

    if ($options->{tcpflags}) {
	ruleset_addrule($ruleset, $chain, "-p tcp -j PVEFW-tcpflags");
    }
}

sub ruleset_create_vm_chain {
    my ($ruleset, $chain, $options, $macaddr, $ipfilter_ipset, $direction) = @_;

    ruleset_create_chain($ruleset, $chain);
    my $accept = generate_nfqueue($options);

    if (!(defined($options->{dhcp}) && $options->{dhcp} == 0)) {
	if ($direction eq 'OUT') {
	    ruleset_generate_rule($ruleset, $chain, { action => 'PVEFW-SET-ACCEPT-MARK',
						      proto => 'udp', sport => 68, dport => 67 });
	} else {
	    ruleset_generate_rule($ruleset, $chain, { action => 'ACCEPT',
						      proto => 'udp', sport => 67, dport => 68 });
	}
    }

    if ($direction eq 'OUT') {
	if (defined($macaddr) && !(defined($options->{macfilter}) && $options->{macfilter} == 0)) {
	    ruleset_addrule($ruleset, $chain, "-m mac ! --mac-source $macaddr -j DROP");
	}
	if ($ipfilter_ipset) {
	    ruleset_addrule($ruleset, $chain, "-m set ! --match-set $ipfilter_ipset src -j DROP");
	}
	ruleset_addrule($ruleset, $chain, "-j MARK --set-mark 0"); # clear mark
    }
}

sub ruleset_add_group_rule {
    my ($ruleset, $cluster_conf, $chain, $rule, $direction, $action) = @_;

    my $group = $rule->{action};
    my $group_chain = "GROUP-$group-$direction";
    if(!ruleset_chain_exist($ruleset, $group_chain)){
	generate_group_rules($ruleset, $cluster_conf, $group);
    }

    if ($direction eq 'OUT' && $rule->{iface_out}) {
	ruleset_addrule($ruleset, $chain, "-o $rule->{iface_out} -j $group_chain");
    } elsif ($direction eq 'IN' && $rule->{iface_in}) {
	ruleset_addrule($ruleset, $chain, "-i $rule->{iface_in} -j $group_chain");
    } else {
	ruleset_addrule($ruleset, $chain, "-j $group_chain");
    }

    ruleset_addrule($ruleset, $chain, "-m mark --mark 1 -j $action");
}

sub ruleset_generate_vm_rules {
    my ($ruleset, $rules, $cluster_conf, $vmfw_conf, $chain, $netid, $direction, $options) = @_;

    my $lc_direction = lc($direction);

    my $in_accept = generate_nfqueue($options);

    foreach my $rule (@$rules) {
	next if $rule->{iface} && $rule->{iface} ne $netid;
	next if !$rule->{enable} || $rule->{errors};
	if ($rule->{type} eq 'group') {
	    ruleset_add_group_rule($ruleset, $cluster_conf, $chain, $rule, $direction,
				   $direction eq 'OUT' ? 'RETURN' : $in_accept);
	} else {
	    next if $rule->{type} ne $lc_direction;
	    eval {
		if ($direction eq 'OUT') {
		    ruleset_generate_rule($ruleset, $chain, $rule,
					  { ACCEPT => "PVEFW-SET-ACCEPT-MARK", REJECT => "PVEFW-reject" },
					  undef, $cluster_conf, $vmfw_conf);
		} else {
		    ruleset_generate_rule($ruleset, $chain, $rule,
					  { ACCEPT => $in_accept , REJECT => "PVEFW-reject" },
					  undef, $cluster_conf, $vmfw_conf);
		}
	    };
	    warn $@ if $@;
	}
    }
}

sub generate_nfqueue {
    my ($options) = @_;

    if ($options->{ips}) {
	my $action = "NFQUEUE";
	if ($options->{ips_queues} && $options->{ips_queues} =~ m/^(\d+)(:(\d+))?$/) {
	    if (defined($3) && defined($1)) {
		$action .= " --queue-balance $1:$3";
	    } elsif (defined($1)) {
		$action .= " --queue-num $1";
	    }
	}
	$action .= " --queue-bypass" if $feature_ipset_nomatch; #need kernel 3.10
	return $action;
    } else {
	return "ACCEPT";
    }
}

sub ruleset_generate_vm_ipsrules {
    my ($ruleset, $options, $direction, $iface) = @_;

    if ($options->{ips} && $direction eq 'IN') {
	my $nfqueue = generate_nfqueue($options);

	if (!ruleset_chain_exist($ruleset, "PVEFW-IPS")) {
	    ruleset_create_chain($ruleset, "PVEFW-IPS");
	}

        ruleset_addrule($ruleset, "PVEFW-IPS", "-m physdev --physdev-out $iface --physdev-is-bridged -j $nfqueue");
    }
}

sub generate_venet_rules_direction {
    my ($ruleset, $cluster_conf, $vmfw_conf, $vmid, $ip, $direction) = @_;

    my $lc_direction = lc($direction);

    my $rules = $vmfw_conf->{rules};

    my $options = $vmfw_conf->{options};
    my $loglevel = get_option_log_level($options, "log_level_${lc_direction}");

    my $chain = "venet0-$vmid-$direction";

    my $ipfilter_ipset = compute_ipset_chain_name($vmid, 'ipfilter')
	if $vmfw_conf->{ipset}->{ipfilter};	

    ruleset_create_vm_chain($ruleset, $chain, $options, undef, $ipfilter_ipset, $direction);

    ruleset_generate_vm_rules($ruleset, $rules, $cluster_conf, $vmfw_conf, $chain, 'venet', $direction);

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

    if ($direction eq 'OUT') {
	ruleset_generate_rule_insert($ruleset, "PVEFW-VENET-OUT", {
	    action => $chain,
	    source => $ip,
	    iface_in => 'venet0'});
    } else {
	ruleset_generate_rule($ruleset, "PVEFW-VENET-IN", {
	    action => $chain,
	    dest => $ip,
	    iface_out => 'venet0'});
    }
}

sub generate_tap_rules_direction {
    my ($ruleset, $cluster_conf, $iface, $netid, $macaddr, $vmfw_conf, $vmid, $direction) = @_;

    my $lc_direction = lc($direction);

    my $rules = $vmfw_conf->{rules};

    my $options = $vmfw_conf->{options};
    my $loglevel = get_option_log_level($options, "log_level_${lc_direction}");

    my $tapchain = "$iface-$direction";

    my $ipfilter_ipset = compute_ipset_chain_name($vmid, 'ipfilter')
	if $vmfw_conf->{ipset}->{ipfilter};	

    ruleset_create_vm_chain($ruleset, $tapchain, $options, $macaddr, $ipfilter_ipset, $direction);

    ruleset_generate_vm_rules($ruleset, $rules, $cluster_conf, $vmfw_conf, $tapchain, $netid, $direction, $options);

    ruleset_generate_vm_ipsrules($ruleset, $options, $direction, $iface);

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
	ruleset_addrule($ruleset, "PVEFW-FWBR-IN",
			"-m physdev --physdev-is-bridged --physdev-out $iface -j $tapchain");
    } else {
	ruleset_addrule($ruleset, "PVEFW-FWBR-OUT",
			"-m physdev --physdev-is-bridged --physdev-in $iface -j $tapchain");
    }
}

sub enable_host_firewall {
    my ($ruleset, $hostfw_conf, $cluster_conf) = @_;

    my $options = $hostfw_conf->{options};
    my $cluster_options = $cluster_conf->{options};
    my $rules = $hostfw_conf->{rules};
    my $cluster_rules = $cluster_conf->{rules};

    # host inbound firewall
    my $chain = "PVEFW-HOST-IN";
    ruleset_create_chain($ruleset, $chain);

    my $loglevel = get_option_log_level($options, "log_level_in");

    ruleset_addrule($ruleset, $chain, "-i lo -j ACCEPT");

    ruleset_chain_add_conn_filters($ruleset, $chain, 'ACCEPT');
    ruleset_chain_add_input_filters($ruleset, $chain, $options, $cluster_conf, $loglevel);

    # we use RETURN because we need to check also tap rules
    my $accept_action = 'RETURN';

    ruleset_addrule($ruleset, $chain, "-p igmp -j $accept_action"); # important for multicast

    # add host rules first, so that cluster wide rules can be overwritten
    foreach my $rule (@$rules, @$cluster_rules) {
	next if !$rule->{enable} || $rule->{errors};

	$rule->{iface_in} = $rule->{iface} if $rule->{iface};

	eval {
	    if ($rule->{type} eq 'group') {
		ruleset_add_group_rule($ruleset, $cluster_conf, $chain, $rule, 'IN', $accept_action);
	    } elsif ($rule->{type} eq 'in') {
		ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" },
				      undef, $cluster_conf, $hostfw_conf);
	    }
	};
	warn $@ if $@;
	delete $rule->{iface_in};
    }

    # allow standard traffic for management ipset (includes cluster network)
    my $mngmnt_ipset_chain = compute_ipset_chain_name(0, "management");
    my $mngmntsrc = "-m set --match-set ${mngmnt_ipset_chain} src";
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 8006 -j $accept_action");  # PVE API
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 5900:5999 -j $accept_action");  # PVE VNC Console
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 3128 -j $accept_action");  # SPICE Proxy
    ruleset_addrule($ruleset, $chain, "$mngmntsrc -p tcp --dport 22 -j $accept_action");  # SSH

    my $localnet = local_network();

    # corosync
    if ($localnet) {
	my $corosync_rule = "-p udp --dport 5404:5405 -j $accept_action";
	ruleset_addrule($ruleset, $chain, "-s $localnet -d $localnet $corosync_rule");
	ruleset_addrule($ruleset, $chain, "-s $localnet -m addrtype --dst-type MULTICAST $corosync_rule");
    }

    # implement input policy
    my $policy = $cluster_options->{policy_in} || 'DROP'; # allow nothing by default
    ruleset_add_chain_policy($ruleset, $chain, 0, $policy, $loglevel, $accept_action);

    # host outbound firewall
    $chain = "PVEFW-HOST-OUT";
    ruleset_create_chain($ruleset, $chain);

    $loglevel = get_option_log_level($options, "log_level_out");

    ruleset_addrule($ruleset, $chain, "-o lo -j ACCEPT");

    ruleset_chain_add_conn_filters($ruleset, $chain, 'ACCEPT');

    # we use RETURN because we may want to check other thigs later
    $accept_action = 'RETURN';

    ruleset_addrule($ruleset, $chain, "-p igmp -j $accept_action"); # important for multicast

    # add host rules first, so that cluster wide rules can be overwritten
    foreach my $rule (@$rules, @$cluster_rules) {
	next if !$rule->{enable} || $rule->{errors};

	$rule->{iface_out} = $rule->{iface} if $rule->{iface};
	eval {
	    if ($rule->{type} eq 'group') {
		ruleset_add_group_rule($ruleset, $cluster_conf, $chain, $rule, 'OUT', $accept_action);
	    } elsif ($rule->{type} eq 'out') {
		ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" },
				      undef, $cluster_conf, $hostfw_conf);
	    }
	};
	warn $@ if $@;
	delete $rule->{iface_out};
    }

    # allow standard traffic on cluster network
    if ($localnet) {
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 8006 -j $accept_action");  # PVE API
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 22 -j $accept_action");  # SSH
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 5900:5999 -j $accept_action");  # PVE VNC Console
	ruleset_addrule($ruleset, $chain, "-d $localnet -p tcp --dport 3128 -j $accept_action");  # SPICE Proxy

	my $corosync_rule = "-p udp --dport 5404:5405 -j $accept_action";
	ruleset_addrule($ruleset, $chain, "-d $localnet $corosync_rule");
	ruleset_addrule($ruleset, $chain, "-m addrtype --dst-type MULTICAST $corosync_rule");
    }

    # implement output policy
    $policy = $cluster_options->{policy_out} || 'ACCEPT'; # allow everything by default
    ruleset_add_chain_policy($ruleset, $chain, 0, $policy, $loglevel, $accept_action);

    ruleset_addrule($ruleset, "PVEFW-OUTPUT", "-j PVEFW-HOST-OUT");
    ruleset_addrule($ruleset, "PVEFW-INPUT", "-j PVEFW-HOST-IN");
}

sub generate_group_rules {
    my ($ruleset, $cluster_conf, $group) = @_;

    my $rules = $cluster_conf->{groups}->{$group};

    if (!$rules) {
	warn "no such security group '$group'\n";
	$rules = []; # create empty chain
    }

    my $chain = "GROUP-${group}-IN";

    ruleset_create_chain($ruleset, $chain);
    ruleset_addrule($ruleset, $chain, "-j MARK --set-mark 0"); # clear mark

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'in';
	ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => "PVEFW-SET-ACCEPT-MARK", REJECT => "PVEFW-reject" }, undef, $cluster_conf);
    }

    $chain = "GROUP-${group}-OUT";

    ruleset_create_chain($ruleset, $chain);
    ruleset_addrule($ruleset, $chain, "-j MARK --set-mark 0"); # clear mark

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'out';
	# we use PVEFW-SET-ACCEPT-MARK (Instead of ACCEPT) because we need to
	# check also other tap rules later
	ruleset_generate_rule($ruleset, $chain, $rule,
			      { ACCEPT => 'PVEFW-SET-ACCEPT-MARK', REJECT => "PVEFW-reject" }, undef, $cluster_conf);
    }
}

my $MAX_NETS = 32;
my $valid_netdev_names = {};
for (my $i = 0; $i < $MAX_NETS; $i++)  {
    $valid_netdev_names->{"net$i"} = 1;
}

sub parse_fw_rule {
    my ($prefix, $line, $cluster_conf, $fw_conf, $rule_env, $verbose) = @_;

    my $orig_line = $line;

    my $rule = {};

    # we can add single line comments to the end of the rule
    if ($line =~ s/#\s*(.*?)\s*$//) {
	$rule->{comment} = decode('utf8', $1);
    }

    # we can disable a rule when prefixed with '|'

    $rule->{enable} = $line =~ s/^\|// ? 0 : 1;

    $line =~ s/^(\S+)\s+(\S+)\s*// ||
 	die "unable to parse rule: $line\n";

    $rule->{type} = lc($1);
    $rule->{action} = $2;

    if ($rule->{type} eq  'in' || $rule->{type} eq 'out') {
	if ($rule->{action} =~ m/^(\S+)\((ACCEPT|DROP|REJECT)\)$/) {
	    $rule->{macro} = $1;
	    $rule->{action} = $2;
	}
    }

    while (length($line)) {
	if ($line =~ s/^-i (\S+)\s*//) {
	    $rule->{iface} = $1;
	    next;
	}

	last if $rule->{type} eq 'group';

	if ($line =~ s/^-p (\S+)\s*//) {
	    $rule->{proto} = $1;
	    next;
	}

	if ($line =~ s/^-dport (\S+)\s*//) {
	    $rule->{dport} = $1;
	    next;
	}

	if ($line =~ s/^-sport (\S+)\s*//) {
	    $rule->{sport} = $1;
	    next;
	}
	if ($line =~ s/^-source (\S+)\s*//) {
	    $rule->{source} = $1;
	    next;
	}
	if ($line =~ s/^-dest (\S+)\s*//) {
	    $rule->{dest} = $1;
	    next;
	}

	last;
    }

    die "unable to parse rule parameters: $line\n" if length($line);

    $rule = verify_rule($rule, $cluster_conf, $fw_conf, $rule_env, 1);
    if ($verbose && $rule->{errors}) {
	warn "$prefix - errors in rule parameters: $orig_line\n";
	foreach my $p (keys %{$rule->{errors}}) {
	    warn "  $p: $rule->{errors}->{$p}\n";
	}
    }

    return $rule;
}

sub parse_vmfw_option {
    my ($line) = @_;

    my ($opt, $value);

    my $loglevels = "emerg|alert|crit|err|warning|notice|info|debug|nolog";

    if ($line =~ m/^(enable|dhcp|macfilter|ips):\s*(0|1)\s*$/i) {
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
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub parse_hostfw_option {
    my ($line) = @_;

    my ($opt, $value);

    my $loglevels = "emerg|alert|crit|err|warning|notice|info|debug|nolog";

    if ($line =~ m/^(enable|nosmurfs|tcpflags):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(log_level_in|log_level_out|tcp_flags_log_level|smurf_log_level):\s*(($loglevels)\s*)?$/i) {
	$opt = lc($1);
	$value = $2 ? lc($3) : '';
    } elsif ($line =~ m/^(nf_conntrack_max|nf_conntrack_tcp_timeout_established):\s*(\d+)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } else {
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
    } elsif ($line =~ m/^(policy_(in|out)):\s*(ACCEPT|DROP|REJECT)\s*$/i) {
	$opt = lc($1);
	$value = uc($3);
    } else {
	die "can't parse option '$line'\n"
    }

    return ($opt, $value);
}

sub resolve_alias {
    my ($clusterfw_conf, $fw_conf, $cidr) = @_;

    if ($cidr !~ m/^\d/) {
	my $alias = lc($cidr);
	my $e = $fw_conf->{aliases}->{$alias} if $fw_conf;
	$e = $clusterfw_conf->{aliases}->{$alias} if !$e && $clusterfw_conf;
	return $e->{cidr} if $e;
	
	die "no such alias '$cidr'\n";
    }

    return $cidr;
}

sub parse_alias {
    my ($line) = @_;

    # we can add single line comments to the end of the line
    my $comment = decode('utf8', $1) if $line =~ s/\s*#\s*(.*?)\s*$//;

    if ($line =~ m/^(\S+)\s(\S+)$/) {
	my ($name, $cidr) = ($1, $2);
	$cidr =~ s|/32$||;
	pve_verify_ipv4_or_cidr($cidr);
	my $data = {
	    name => $name,
	    cidr => $cidr,
	};
	$data->{comment} = $comment  if $comment;
	return $data;
    }

    return undef;
}

sub generic_fw_config_parser {
    my ($filename, $fh, $verbose, $cluster_conf, $empty_conf, $rule_env) = @_;

    my $section;
    my $group;

    my $res = $empty_conf;

    while (defined(my $line = <$fh>)) {
	next if $line =~ m/^#/;
	next if $line =~ m/^\s*$/;

	chomp $line;

	my $linenr = $fh->input_line_number();
	my $prefix = "$filename (line $linenr)";

	if ($empty_conf->{options} && ($line =~ m/^\[options\]$/i)) {
	    $section = 'options';
	    next;
	}

	if ($empty_conf->{aliases} && ($line =~ m/^\[aliases\]$/i)) {
	    $section = 'aliases';
	    next;
	}

	if ($empty_conf->{groups} && ($line =~ m/^\[group\s+(\S+)\]\s*(?:#\s*(.*?)\s*)?$/i)) {
	    $section = 'groups';
	    $group = lc($1);
	    my $comment = $2;
	    eval {
		die "security group name too long\n" if length($group) > $max_group_name_length;
		die "invalid security group name '$group'\n" if $group !~ m/^${security_group_name_pattern}$/;
	    };
	    if (my $err = $@) {
		($section, $group, $comment) = undef;
		warn "$prefix: $err";
		next;
	    }
	    
	    $res->{$section}->{$group} = [];
	    $res->{group_comments}->{$group} =  decode('utf8', $comment)
		if $comment;
	    next;
	}

	if ($empty_conf->{rules} && ($line =~ m/^\[rules\]$/i)) {
	    $section = 'rules';
	    next;
	}

	if ($empty_conf->{ipset} && ($line =~ m/^\[ipset\s+(\S+)\]\s*(?:#\s*(.*?)\s*)?$/i)) {
	    $section = 'ipset';
	    $group = lc($1);
	    my $comment = $2;
	    eval {	
		die "ipset name too long\n" if length($group) > $max_ipset_name_length;
		die "invalid ipset name '$group'\n" if $group !~ m/^${ipset_name_pattern}$/;
	    };
	    if (my $err = $@) {
		($section, $group, $comment) = undef;
		warn "$prefix: $err";
		next;
	    }

	    $res->{$section}->{$group} = [];
	    $res->{ipset_comments}->{$group} = decode('utf8', $comment)
		if $comment;
	    next;
	}

	if (!$section) {
	    warn "$prefix: skip line - no section\n";
	    next;
	}

	if ($section eq 'options') {
	    eval {
		my ($opt, $value);
		if ($rule_env eq 'cluster') {
		    ($opt, $value) = parse_clusterfw_option($line);
		} elsif ($rule_env eq 'host') {
		    ($opt, $value) = parse_hostfw_option($line);
		} else {
		    ($opt, $value) = parse_vmfw_option($line);
		}
		$res->{options}->{$opt} = $value;
	    };
	    warn "$prefix: $@" if $@;
	} elsif ($section eq 'aliases') {
	    eval {
		my $data = parse_alias($line);
		$res->{aliases}->{lc($data->{name})} = $data;
	    };
	    warn "$prefix: $@" if $@;
	} elsif ($section eq 'rules') {
	    my $rule;
	    eval { $rule = parse_fw_rule($prefix, $line, $cluster_conf, $res, $rule_env, $verbose); };
	    if (my $err = $@) {
		warn "$prefix: $err";
		next;
	    }
	    push @{$res->{$section}}, $rule;
	} elsif ($section eq 'groups') {
	    my $rule;
	    eval { $rule = parse_fw_rule($prefix, $line, $cluster_conf, undef, 'group', $verbose); };
	    if (my $err = $@) {
		warn "$prefix: $err";
		next;
	    }
	    push @{$res->{$section}->{$group}}, $rule;
	} elsif ($section eq 'ipset') {
	    # we can add single line comments to the end of the rule
	    my $comment = decode('utf8', $1) if $line =~ s/#\s*(.*?)\s*$//;

	    $line =~ m/^(\!)?\s*(\S+)\s*$/;
	    my $nomatch = $1;
	    my $cidr = $2;
	    my $errors;

	    if ($nomatch && !$feature_ipset_nomatch) {
		$errors->{nomatch} = "nomatch not supported by kernel";
	    }

	    eval { 
		if ($cidr =~ m/^${ip_alias_pattern}$/) {
		    resolve_alias($cluster_conf, $res, $cidr); # make sure alias exists
		} else {
		    $cidr =~ s|/32$||;
		    pve_verify_ipv4_or_cidr_or_alias($cidr);
		}
	    };
	    if (my $err = $@) {
		chomp $err;
		$errors->{cidr} = $err;
	    }

	    my $entry = { cidr => $cidr };
	    $entry->{nomatch} = 1 if $nomatch;
	    $entry->{comment} = $comment if $comment;
	    $entry->{errors} =  $errors if $errors;

	    if ($verbose && $errors) {
		warn "$prefix - errors in ipset '$group': $line\n";
		foreach my $p (keys %{$errors}) {
		    warn "  $p: $errors->{$p}\n";
		}
	    }

	    push @{$res->{$section}->{$group}}, $entry;
	} else {
	    warn "$prefix: skip line - unknown section\n";
	    next;
	}
    }

    return $res;
}

sub parse_hostfw_config {
    my ($filename, $fh, $cluster_conf, $verbose) = @_;

    my $empty_conf = { rules => [], options => {}};

    return generic_fw_config_parser($filename, $fh, $verbose, $cluster_conf, $empty_conf, 'host');
}

sub parse_vmfw_config {
    my ($filename, $fh, $cluster_conf, $rule_env, $verbose) = @_;

    my $empty_conf = {
	rules => [],
	options => {},
	aliases => {},
	ipset => {} ,
	ipset_comments => {},
    };

    return generic_fw_config_parser($filename, $fh, $verbose, $cluster_conf, $empty_conf, $rule_env);
}

sub parse_clusterfw_config {
    my ($filename, $fh, $verbose) = @_;

    my $section;
    my $group;

    my $empty_conf = {
	rules => [],
	options => {},
	aliases => {},
	groups => {},
	group_comments => {},
	ipset => {} ,
	ipset_comments => {},
    };

    return generic_fw_config_parser($filename, $fh, $verbose, $empty_conf, $empty_conf, 'cluster');
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
    my ($cluster_conf, $rule_env, $vmid, $dir, $verbose) = @_;

    my $vmfw_conf = {};

    $dir = $pvefw_conf_dir if !defined($dir);

    my $filename = "$dir/$vmid.fw";
    if (my $fh = IO::File->new($filename, O_RDONLY)) {
	$vmfw_conf = parse_vmfw_config($filename, $fh, $cluster_conf, $rule_env, $verbose);
	$vmfw_conf->{vmid} = $vmid;
    }

    return $vmfw_conf;
}

my $format_rules = sub {
    my ($rules, $allow_iface) = @_;

    my $raw = '';

    foreach my $rule (@$rules) {
	if ($rule->{type} eq  'in' || $rule->{type} eq 'out' || $rule->{type} eq 'group') {
	    $raw .= '|' if defined($rule->{enable}) && !$rule->{enable};
	    $raw .= uc($rule->{type});
	    if ($rule->{macro}) {
		$raw .= " $rule->{macro}($rule->{action})";
	    } else {
		$raw .= " " . $rule->{action};
	    }
	    if ($allow_iface && $rule->{iface}) {
		$raw .= " -i $rule->{iface}";
	    }

	    if ($rule->{type} ne  'group')  {
		$raw .= " -source $rule->{source}" if $rule->{source};
		$raw .= " -dest $rule->{dest}" if $rule->{dest};
		$raw .= " -p $rule->{proto}" if $rule->{proto};
		$raw .= " -dport $rule->{dport}" if $rule->{dport};
		$raw .= " -sport $rule->{sport}" if $rule->{sport};
	    }

	    $raw .= " # " . encode('utf8', $rule->{comment})
		if $rule->{comment} && $rule->{comment} !~ m/^\s*$/;
	    $raw .= "\n";
	} else {
	    die "unknown rule type '$rule->{type}'";
	}
    }

    return $raw;
};

my $format_options = sub {
    my ($options) = @_;

    my $raw = '';

    $raw .= "[OPTIONS]\n\n";
    foreach my $opt (keys %$options) {
	$raw .= "$opt: $options->{$opt}\n";
    }
    $raw .= "\n";

    return $raw;
};

my $format_aliases = sub {
    my ($aliases) = @_;

    my $raw = '';

    $raw .= "[ALIASES]\n\n";
    foreach my $k (keys %$aliases) {
	my $e = $aliases->{$k};
	$raw .= "$e->{name} $e->{cidr}";
	$raw .= " # " . encode('utf8', $e->{comment})
	    if $e->{comment} && $e->{comment} !~ m/^\s*$/;
	$raw .= "\n";
    }
    $raw .= "\n";

    return $raw;
};

my $format_ipsets = sub {
    my ($fw_conf) = @_;
    
    my $raw = '';

    foreach my $ipset (sort keys %{$fw_conf->{ipset}}) {
	if (my $comment = $fw_conf->{ipset_comments}->{$ipset}) {
	    my $utf8comment = encode('utf8', $comment);
	    $raw .= "[IPSET $ipset] # $utf8comment\n\n";
	} else {
	    $raw .= "[IPSET $ipset]\n\n";
	}
	my $options = $fw_conf->{ipset}->{$ipset};

	my $nethash = {};
	foreach my $entry (@$options) {
	    $nethash->{$entry->{cidr}} = $entry;
	}

	foreach my $cidr (sort keys %$nethash) {
	    my $entry = $nethash->{$cidr};
	    my $line = $entry->{nomatch} ? '!' : '';
	    $line .= $entry->{cidr};
	    $line .= " # " . encode('utf8', $entry->{comment})
		if $entry->{comment} && $entry->{comment} !~ m/^\s*$/;
	    $raw .= "$line\n";
	}

	$raw .= "\n";
    }

    return $raw;
};

sub save_vmfw_conf {
    my ($vmid, $vmfw_conf) = @_;

    my $raw = '';

    my $options = $vmfw_conf->{options};
    $raw .= &$format_options($options) if $options && scalar(keys %$options);

    my $aliases = $vmfw_conf->{aliases};
    $raw .= &$format_aliases($aliases) if $aliases && scalar(keys %$aliases);

    $raw .= &$format_ipsets($vmfw_conf) if $vmfw_conf->{ipset};

    my $rules = $vmfw_conf->{rules} || [];
    if ($rules && scalar(@$rules)) {
	$raw .= "[RULES]\n\n";
	$raw .= &$format_rules($rules, 1);
	$raw .= "\n";
    }

    mkdir $pvefw_conf_dir;

    my $filename = "$pvefw_conf_dir/$vmid.fw";
    PVE::Tools::file_set_contents($filename, $raw);
}

sub read_vm_firewall_configs {
    my ($cluster_conf, $vmdata, $dir, $verbose) = @_;

    my $vmfw_configs = {};

    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	my $vmfw_conf = load_vmfw_conf($cluster_conf, 'vm', $vmid, $dir, $verbose);
	next if !$vmfw_conf->{options}; # skip if file does not exists
	$vmfw_configs->{$vmid} = $vmfw_conf;
    }
    foreach my $vmid (keys %{$vmdata->{openvz}}) {
	my $vmfw_conf = load_vmfw_conf($cluster_conf, 'ct', $vmid, $dir, $verbose);
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
    $pve_std_chains->{$chain} = [];

    push @{$pve_std_chains->{$chain}}, get_log_rule_base($chain, 0, "DROP: ", $loglevel) if $loglevel;
    push @{$pve_std_chains->{$chain}}, "-j DROP";

    # same as shorewall logflags action.
    $loglevel = get_option_log_level($options, 'tcp_flags_log_level');
    $chain = 'PVEFW-logflags';
    $pve_std_chains->{$chain} = [];

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
    my ($ipset_ruleset, $clusterfw_conf, $fw_conf) = @_;

    foreach my $ipset (keys %{$fw_conf->{ipset}}) {
	my $ipset_chain = compute_ipset_chain_name($fw_conf->{vmid}, $ipset);
	generate_ipset($ipset_ruleset, $ipset_chain, $fw_conf->{ipset}->{$ipset}, $clusterfw_conf, $fw_conf);
    }
}

sub generate_ipset {
    my ($ipset_ruleset, $name, $options, $clusterfw_conf, $fw_conf) = @_;

    die "duplicate ipset chain '$name'\n" if defined($ipset_ruleset->{$name});

    my $hashsize = scalar(@$options);
    if ($hashsize <= 64) {
	$hashsize = 64;
    } else {
	$hashsize = round_powerof2($hashsize);
    }

    $ipset_ruleset->{$name} = ["create $name hash:net family inet hashsize $hashsize maxelem $hashsize"];

    # remove duplicates
    my $nethash = {};
    foreach my $entry (@$options) {
	next if $entry->{errors}; # skip entries with errors
	eval {
	    my $cidr = resolve_alias($clusterfw_conf, $fw_conf, $entry->{cidr});
	    $nethash->{$cidr} = { cidr => $cidr, nomatch => $entry->{nomatch} };
	};
	warn $@ if $@;
    }

    foreach my $cidr (sort keys %$nethash) {
	my $entry = $nethash->{$cidr};

	my $cmd = "add $name $cidr";
	if ($entry->{nomatch}) {
	    if ($feature_ipset_nomatch) {
		push @{$ipset_ruleset->{$name}}, "$cmd nomatch";
	    } else {
		warn "ignore !$cidr - nomatch not supported by kernel\n";
	    }
	} else {
	    push @{$ipset_ruleset->{$name}}, $cmd;
	}
    }
}

sub round_powerof2 {
    my ($int) = @_;

    $int--;
    $int |= $int >> $_ foreach (1,2,4,8,16);
    return ++$int;
}

sub load_clusterfw_conf {
    my ($filename, $verbose) = @_;

    $filename = $clusterfw_conf_filename if !defined($filename);

    my $cluster_conf = {};
    if (my $fh = IO::File->new($filename, O_RDONLY)) {
	$cluster_conf = parse_clusterfw_config($filename, $fh, $verbose);
    }

    return $cluster_conf;
}

sub save_clusterfw_conf {
    my ($cluster_conf) = @_;

    my $raw = '';

    my $options = $cluster_conf->{options};
    $raw .= &$format_options($options) if $options && scalar(keys %$options);

    my $aliases = $cluster_conf->{aliases};
    $raw .= &$format_aliases($aliases) if $aliases && scalar(keys %$aliases);

    $raw .= &$format_ipsets($cluster_conf) if $cluster_conf->{ipset};
 
    my $rules = $cluster_conf->{rules};
    if ($rules && scalar(@$rules)) {
	$raw .= "[RULES]\n\n";
	$raw .= &$format_rules($rules, 1);
	$raw .= "\n";
    }

    if ($cluster_conf->{groups}) {
	foreach my $group (sort keys %{$cluster_conf->{groups}}) {
	    my $rules = $cluster_conf->{groups}->{$group};
	    if (my $comment = $cluster_conf->{group_comments}->{$group}) {
		my $utf8comment = encode('utf8', $comment);
		$raw .= "[group $group] # $utf8comment\n\n";
	    } else {
		$raw .= "[group $group]\n\n";
	    }

	    $raw .= &$format_rules($rules, 0);
	    $raw .= "\n";
	}
    }

    mkdir $pvefw_conf_dir;
    PVE::Tools::file_set_contents($clusterfw_conf_filename, $raw);
}

sub load_hostfw_conf {
    my ($cluster_conf, $filename, $verbose) = @_;

    $filename = $hostfw_conf_filename if !defined($filename);

    my $hostfw_conf = {};
    if (my $fh = IO::File->new($filename, O_RDONLY)) {
	$hostfw_conf = parse_hostfw_config($filename, $fh, $cluster_conf, $verbose);
    }
    return $hostfw_conf;
}

sub save_hostfw_conf {
    my ($hostfw_conf) = @_;

    my $raw = '';

    my $options = $hostfw_conf->{options};
    $raw .= &$format_options($options) if $options && scalar(keys %$options);

    my $rules = $hostfw_conf->{rules};
    if ($rules && scalar(@$rules)) {
	$raw .= "[RULES]\n\n";
	$raw .= &$format_rules($rules, 1);
	$raw .= "\n";
    }

    PVE::Tools::file_set_contents($hostfw_conf_filename, $raw);
}

sub compile {
    my ($cluster_conf, $hostfw_conf, $vmdata, $verbose) = @_;

    my $vmfw_configs;

    if ($vmdata) { # test mode
	my $testdir = $vmdata->{testdir} || die "no test directory specified";
	my $filename = "$testdir/cluster.fw";
	$cluster_conf = load_clusterfw_conf($filename, $verbose);

	$filename = "$testdir/host.fw";
	$hostfw_conf = load_hostfw_conf($cluster_conf, $filename, $verbose);

	$vmfw_configs = read_vm_firewall_configs($cluster_conf, $vmdata, $testdir, $verbose);
    } else { # normal operation
	$cluster_conf = load_clusterfw_conf(undef, $verbose) if !$cluster_conf;

	$hostfw_conf = load_hostfw_conf($cluster_conf, undef, $verbose) if !$hostfw_conf;

	$vmdata = read_local_vm_config();
	$vmfw_configs = read_vm_firewall_configs($cluster_conf, $vmdata, undef, $verbose);
    }

    $cluster_conf->{ipset}->{venet0} = [];
    my $venet0_ipset_chain = compute_ipset_chain_name(0, 'venet0');

    my $localnet;
    if ($cluster_conf->{aliases}->{local_network}) {
	$localnet = $cluster_conf->{aliases}->{local_network}->{cidr};
    } else {
	$localnet = local_network() || '127.0.0.0/8';
	$cluster_conf->{aliases}->{local_network} = { cidr => $localnet };
    }

    push @{$cluster_conf->{ipset}->{management}}, { cidr => $localnet };

    return ({}, {}) if !$cluster_conf->{options}->{enable};

    my $ruleset = {};

    ruleset_create_chain($ruleset, "PVEFW-INPUT");
    ruleset_create_chain($ruleset, "PVEFW-OUTPUT");

    ruleset_create_chain($ruleset, "PVEFW-FORWARD");

    my $hostfw_options = $hostfw_conf->{options} || {};

    # fixme: what log level should we use here?
    my $loglevel = get_option_log_level($hostfw_options, "log_level_out");

    ruleset_chain_add_conn_filters($ruleset, "PVEFW-FORWARD", "ACCEPT");


    ruleset_create_chain($ruleset, "PVEFW-VENET-OUT");
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-i venet0 -m set --match-set ${venet0_ipset_chain} src -j PVEFW-VENET-OUT");
    ruleset_addrule($ruleset, "PVEFW-INPUT", "-i venet0 -m set --match-set ${venet0_ipset_chain} src -j PVEFW-VENET-OUT");

    ruleset_create_chain($ruleset, "PVEFW-FWBR-IN");
    ruleset_chain_add_input_filters($ruleset, "PVEFW-FWBR-IN", $hostfw_options, $cluster_conf, $loglevel);

    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-m physdev --physdev-is-bridged --physdev-in fwln+ -j PVEFW-FWBR-IN");

    ruleset_create_chain($ruleset, "PVEFW-FWBR-OUT");
    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-m physdev --physdev-is-bridged --physdev-out fwln+ -j PVEFW-FWBR-OUT");

    ruleset_create_chain($ruleset, "PVEFW-VENET-IN");
    ruleset_chain_add_input_filters($ruleset, "PVEFW-VENET-IN", $hostfw_options, $cluster_conf, $loglevel);

    ruleset_addrule($ruleset, "PVEFW-FORWARD", "-o venet0 -m set --match-set ${venet0_ipset_chain} dst -j PVEFW-VENET-IN");

    generate_std_chains($ruleset, $hostfw_options);

    my $hostfw_enable = !(defined($hostfw_options->{enable}) && ($hostfw_options->{enable} == 0));

    my $ipset_ruleset = {};

    if ($hostfw_enable) {
	eval { enable_host_firewall($ruleset, $hostfw_conf, $cluster_conf); };
	warn $@ if $@; # just to be sure - should not happen
    }

    ruleset_addrule($ruleset, "PVEFW-OUTPUT", "-o venet0 -m set --match-set ${venet0_ipset_chain} dst -j PVEFW-VENET-IN");

    # generate firewall rules for QEMU VMs
    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	eval {
	    my $conf = $vmdata->{qemu}->{$vmid};
	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf;
	    return if !$vmfw_conf->{options}->{enable};

	    generate_ipset_chains($ipset_ruleset, $cluster_conf, $vmfw_conf);

	    foreach my $netid (keys %$conf) {
		next if $netid !~ m/^net(\d+)$/;
		my $net = PVE::QemuServer::parse_net($conf->{$netid});
		next if !$net->{firewall};
		my $iface = "tap${vmid}i$1";

		my $macaddr = $net->{macaddr};
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
					     $vmfw_conf, $vmid, 'IN');
		generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
					     $vmfw_conf, $vmid, 'OUT');
	    }
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    # generate firewall rules for OpenVZ containers
    foreach my $vmid (keys %{$vmdata->{openvz}}) {
	eval {
	    my $conf = $vmdata->{openvz}->{$vmid};

	    my $vmfw_conf = $vmfw_configs->{$vmid};
	    return if !$vmfw_conf;
	    return if !$vmfw_conf->{options}->{enable};

	    generate_ipset_chains($ipset_ruleset, $cluster_conf, $vmfw_conf);

	    if ($conf->{ip_address} && $conf->{ip_address}->{value}) {
		my $ip = $conf->{ip_address}->{value};
		$ip =~ s/\s+/,/g;
		parse_address_list($ip); # make sure we have a valid $ip list

		my @ips = split(',', $ip);

		foreach my $singleip (@ips) {
		    my $venet0ipset = {};
		    $venet0ipset->{cidr} = $singleip;
		    push @{$cluster_conf->{ipset}->{venet0}}, $venet0ipset;
		}

		generate_venet_rules_direction($ruleset, $cluster_conf, $vmfw_conf, $vmid, $ip, 'IN');
		generate_venet_rules_direction($ruleset, $cluster_conf, $vmfw_conf, $vmid, $ip, 'OUT');
	    }

	    if ($conf->{netif} && $conf->{netif}->{value}) {
		my $netif = PVE::OpenVZ::parse_netif($conf->{netif}->{value});
		foreach my $netid (keys %$netif) {
		    my $d = $netif->{$netid};

		    my $macaddr = $d->{mac};
		    my $iface = $d->{host_ifname};
		    generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
						 $vmfw_conf, $vmid, 'IN');
		    generate_tap_rules_direction($ruleset, $cluster_conf, $iface, $netid, $macaddr,
						 $vmfw_conf, $vmid, 'OUT');
		}
	    }
	};
	warn $@ if $@; # just to be sure - should not happen
    }

    if(ruleset_chain_exist($ruleset, "PVEFW-IPS")){
	ruleset_insertrule($ruleset, "PVEFW-FORWARD", "-m conntrack --ctstate RELATED,ESTABLISHED -j PVEFW-IPS");
    }

    generate_ipset_chains($ipset_ruleset, undef, $cluster_conf);

    return ($ruleset, $ipset_ruleset);
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
	my $chain = "PVEFW-$h";
	if ($ruleset->{$chain} && !$hooks->{$h}) {
	    $cmdlist .= "-A $h -j $chain\n";
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

    # remove stale _swap chains
    foreach my $chain (keys %$active_chains) {
	if ($chain =~ m/^PVEFW-\S+_swap$/) {
	    $cmdlist .= "destroy $chain\n";
	}
    }

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

    my ($ipset_create_cmdlist, $ipset_delete_cmdlist, $ipset_changes) =
	get_ipset_cmdlist($ipset_ruleset, undef, $verbose);

    my ($cmdlist, $changes) = get_ruleset_cmdlist($ruleset, $verbose);

    if ($verbose) {
	if ($ipset_changes) {
	    print "ipset changes:\n";
	    print $ipset_create_cmdlist if $ipset_create_cmdlist;
	    print $ipset_delete_cmdlist if $ipset_delete_cmdlist;
	}

	if ($changes) {
	    print "iptables changes:\n";
	    print $cmdlist;
	}
    }

    ipset_restore_cmdlist($ipset_create_cmdlist);

    iptables_restore_cmdlist($cmdlist);

    ipset_restore_cmdlist($ipset_delete_cmdlist) if $ipset_delete_cmdlist;

    # test: re-read status and check if everything is up to date
    my $active_chains = iptables_get_chains();
    my $statushash = get_ruleset_status($ruleset, $active_chains, \&iptables_chain_digest, 0);

    my $errors;
    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	if ($stat->{action} ne 'exists') {
	    warn "unable to update chain '$chain'\n";
	    $errors = 1;
	}
    }

    die "unable to apply firewall changes\n" if $errors;

    update_nf_conntrack_max($hostfw_conf);

    update_nf_conntrack_tcp_timeout_established($hostfw_conf);

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

sub update_nf_conntrack_tcp_timeout_established {
    my ($hostfw_conf) = @_;

    my $options = $hostfw_conf->{options} || {};

    my $value = defined($options->{nf_conntrack_tcp_timeout_established}) ? $options->{nf_conntrack_tcp_timeout_established} : 432000;

    PVE::ProcFSTools::write_proc_entry("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", $value);
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

    my $ipset_chains = ipset_get_chains();

    $cmdlist = "";
 
    foreach my $chain (keys %$ipset_chains) {
       $cmdlist .= "flush $chain\n";
       $cmdlist .= "destroy $chain\n";
    }

    ipset_restore_cmdlist($cmdlist) if $cmdlist; 
}

sub init {
    my $cluster_conf = load_clusterfw_conf();
    my $cluster_options = $cluster_conf->{options};
    my $enable = $cluster_options->{enable};

    return if !$enable;

    # load required modules here
}

sub update {
    my $code = sub {

	my $cluster_conf = load_clusterfw_conf();
	my $cluster_options = $cluster_conf->{options};

	if (!$cluster_options->{enable}) {
	    PVE::Firewall::remove_pvefw_chains();
	    return;
	}

	my $hostfw_conf = load_hostfw_conf();

	my ($ruleset, $ipset_ruleset) = compile($cluster_conf, $hostfw_conf);

	apply_ruleset($ruleset, $hostfw_conf, $ipset_ruleset);
    };

    run_locked($code);
}

1;
