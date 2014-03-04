package PVE::Firewall;

use warnings;
use strict;
use Data::Dumper;
use Digest::SHA;
use PVE::ProcFSTools;
use PVE::Tools;
use PVE::QemuServer;
use File::Basename;
use File::Path;
use IO::File;
use Net::IP;
use PVE::Tools qw(run_command lock_file);

use Data::Dumper;

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

sub get_firewall_macros {

    return $pve_fw_parsed_macros if $pve_fw_parsed_macros;

    $pve_fw_parsed_macros = {};

    foreach my $k (keys %$pve_fw_macros) {
	my $name = lc($k);

	my $macro =  $pve_fw_macros->{$k};
	$pve_fw_preferred_macro_names->{$name} = $k;
	$pve_fw_parsed_macros->{$name} = $macro;
    }

    return $pve_fw_parsed_macros;
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

sub iptables {
    my ($cmd) = @_;

    run_command("/sbin/iptables $cmd", outfunc => sub {}, errfunc => sub {});
}

sub iptables_restore_cmdlist {
    my ($cmdlist) = @_;

    run_command("/sbin/iptables-restore -n", input => $cmdlist);
}

sub iptables_get_chains {

    my $res = {};

    # check what chains we want to track
    my $is_pvefw_chain = sub {
	my $name = shift;

	return 1 if $name =~ m/^PVEFW-\S+$/;

	return 1 if $name =~ m/^tap\d+i\d+-(:?IN|OUT)$/;
	return 1 if $name =~ m/^vmbr\d+-(:?FW|IN|OUT)$/;
	return 1 if $name =~ m/^GROUP-(:?[^\s\-]+)-(:?IN|OUT)$/;

	return undef;
    };

    my $table = '';

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
	} else {
	    # simply ignore the rest
	    return;
	}
    };

    run_command("/sbin/iptables-save", outfunc => $parser);

    return $res;
}

sub iptables_chain_exist {
    my ($chain) = @_;

    eval{
	iptables("-n --list $chain");
    };
    return undef if $@;

    return 1;
}

sub iptables_rule_exist {
    my ($rule) = @_;

    eval{
	iptables("-C $rule");
    };
    return undef if $@;

    return 1;
}

sub ruleset_generate_rule {
    my ($ruleset, $chain, $rule, $actions, $goto) = @_;

    return if $rule->{disable};

    my @cmd = ();

    push @cmd, "-m iprange --src-range" if $rule->{nbsource} && $rule->{nbsource} > 1;
    push @cmd, "-s $rule->{source}" if $rule->{source};
    push @cmd, "-m iprange --dst-range" if $rule->{nbdest} && $rule->{nbdest} > 1;
    push @cmd, "-d $rule->{dest}" if $rule->{dest};

    if ($rule->{proto}) {
	push @cmd, "-p $rule->{proto}";

	my $multiport = 0;
	$multiport++ if $rule->{nbdport} && ($rule->{nbdport} > 1);
	$multiport++ if $rule->{nbsport} && ($rule->{nbsport} > 1);

	push @cmd, "--match multiport" if $multiport;

	die "multiport: option '--sports' cannot be used together with '--dports'\n" 
	    if ($multiport == 2) && ($rule->{dport} ne $rule->{sport});

	if ($rule->{dport}) {
	    if ($rule->{proto} && $rule->{proto} eq 'icmp') {
		# Note: we use dport to store --icmp-type
		die "unknown icmp-type '$rule->{dport}'\n" if !defined($icmp_type_names->{$rule->{dport}});
		push @cmd, "-m icmp --icmp-type $rule->{dport}";
	    } else {
		if ($rule->{nbdport} && $rule->{nbdport} > 1) {
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
	    if ($rule->{nbsport} && $rule->{nbsport} > 1) {
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

    if (scalar(@cmd)) {
	my $cmdstr = join(' ', @cmd);
	ruleset_addrule($ruleset, $chain, $cmdstr);
    }
}

sub ruleset_create_chain {
    my ($ruleset, $chain) = @_;

    die "Invalid chain name '$chain' (28 char max)\n" if length($chain) > 28;

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

sub generate_bridge_chains {
    my ($ruleset, $bridge) = @_;

    if (!ruleset_chain_exist($ruleset, "PVEFW-FORWARD")){
	ruleset_create_chain($ruleset, "PVEFW-FORWARD");
	ruleset_addrule($ruleset, "PVEFW-FORWARD", "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
    }

    if (!ruleset_chain_exist($ruleset, "$bridge-FW")) {
	ruleset_create_chain($ruleset, "$bridge-FW");
	ruleset_addrule($ruleset, "PVEFW-FORWARD", "-o $bridge -m physdev --physdev-is-bridged -j $bridge-FW");
	ruleset_addrule($ruleset, "PVEFW-FORWARD", "-i $bridge -m physdev --physdev-is-bridged -j $bridge-FW");
	ruleset_addrule($ruleset, "PVEFW-FORWARD", "-o $bridge -j DROP");  # disable interbridge routing
	ruleset_addrule($ruleset, "PVEFW-FORWARD", "-i $bridge -j DROP"); # disable interbridge routing
    }

    if (!ruleset_chain_exist($ruleset, "$bridge-OUT")) {
	ruleset_create_chain($ruleset, "$bridge-OUT");
	ruleset_addrule($ruleset, "$bridge-FW", "-m physdev --physdev-is-bridged --physdev-is-in -j $bridge-OUT");
    }

    if (!ruleset_chain_exist($ruleset, "$bridge-IN")) {
	ruleset_create_chain($ruleset, "$bridge-IN");
	ruleset_addrule($ruleset, "$bridge-FW", "-m physdev --physdev-is-bridged --physdev-is-out -j $bridge-IN");
	ruleset_addrule($ruleset, "$bridge-FW", "-m mark --mark 1 -j ACCEPT");
	# accept traffic to unmanaged bridge ports
	ruleset_addrule($ruleset, "$bridge-FW", "-m physdev --physdev-is-bridged --physdev-is-out -j ACCEPT ");
    }
}

sub ruleset_add_chain_policy {
    my ($ruleset, $chain, $policy, $loglevel, $accept_action) = @_;

    if ($policy eq 'ACCEPT') {

	ruleset_generate_rule($ruleset, $chain, { action => 'ACCEPT' },
			      { ACCEPT =>  $accept_action});

    } elsif ($policy eq 'DROP') {

	ruleset_addrule($ruleset, $chain, "-j PVEFW-Drop");

	ruleset_addrule($ruleset, $chain, "-j LOG --log-prefix \"$chain-dropped: \" --log-level $loglevel")
	    if defined($loglevel);

	ruleset_addrule($ruleset, $chain, "-j DROP");
    } elsif ($policy eq 'REJECT') {
	ruleset_addrule($ruleset, $chain, "-j PVEFW-Reject");

	ruleset_addrule($ruleset, $chain, "-j LOG --log-prefix \"$chain-reject: \" --log-level $loglevel")
	    if defined($loglevel);

	ruleset_addrule($ruleset, $chain, "-g PVEFW-reject");
    } else {
	# should not happen
	die "internal error: unknown policy '$policy'";
    }
}

sub generate_tap_rules_direction {
    my ($ruleset, $groups_conf, $iface, $netid, $macaddr, $vmfw_conf, $bridge, $direction) = @_;

    my $lc_direction = lc($direction);

    my $rules = $vmfw_conf->{rules};

    my $options = $vmfw_conf->{options};
    my $loglevel = get_option_log_level($options, "log_level_${lc_direction}");

    my $tapchain = "$iface-$direction";

    ruleset_create_chain($ruleset, $tapchain);

    if (!(defined($options->{nosmurfs}) && $options->{nosmurfs} == 0)) {
	ruleset_addrule($ruleset, $tapchain, "-m conntrack --ctstate INVALID,NEW -j PVEFW-smurfs");
    }

    if (!(defined($options->{dhcp}) && $options->{dhcp} == 0)) {
	ruleset_addrule($ruleset, $tapchain, "-p udp -m udp --dport 67:68 -j ACCEPT");
    }

    if ($options->{tcpflags}) {
	ruleset_addrule($ruleset, $tapchain, "-p tcp -j PVEFW-tcpflags");
    }

    ruleset_addrule($ruleset, $tapchain, "-m conntrack --ctstate INVALID -j DROP");
    ruleset_addrule($ruleset, $tapchain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");

    if ($direction eq 'OUT') {
	if (defined($macaddr) && !(defined($options->{macfilter}) && $options->{macfilter} == 0)) {
	    ruleset_addrule($ruleset, $tapchain, "-m mac ! --mac-source $macaddr -j DROP");
	}
	ruleset_addrule($ruleset, $tapchain, "-j MARK --set-mark 0"); # clear mark
    }

    foreach my $rule (@$rules) {
	next if $rule->{iface} && $rule->{iface} ne $netid;
	next if $rule->{disable};
	if ($rule->{type} eq 'group') {
	    my $group_chain = "GROUP-$rule->{action}-$direction"; 
	    if(!ruleset_chain_exist($ruleset, $group_chain)){
		generate_group_rules($ruleset, $groups_conf, $rule->{action});
	    }
	    ruleset_addrule($ruleset, $tapchain, "-j $group_chain");
	    ruleset_addrule($ruleset, $tapchain, "-m mark --mark 1 -j RETURN")
		if $direction eq 'OUT';
	} else {
	    next if $rule->{type} ne $lc_direction;
	    if ($direction eq 'OUT') {
		ruleset_generate_rule($ruleset, $tapchain, $rule, 
				      { ACCEPT => "PVEFW-SET-ACCEPT-MARK", REJECT => "PVEFW-reject" });
	    } else {
		ruleset_generate_rule($ruleset, $tapchain, $rule, { REJECT => "PVEFW-reject" });
	    }
	}
    }

    # implement policy
    my $policy;

    if ($direction eq 'OUT') {
	$policy = $options->{'policy-out'} || 'ACCEPT'; # allow everything by default
    } else {
	$policy = $options->{'policy-in'} || 'DROP'; # allow nothing by default
    }

    my $accept_action = $direction eq 'OUT' ? "PVEFW-SET-ACCEPT-MARK" : "ACCEPT";
    ruleset_add_chain_policy($ruleset, $tapchain, $policy, $loglevel, $accept_action);

    # plug the tap chain to bridge chain
    my $physdevdirection = $direction eq 'IN' ? "out" : "in";
    my $rule = "-m physdev --physdev-$physdevdirection $iface --physdev-is-bridged -j $tapchain";
    ruleset_insertrule($ruleset, "$bridge-$direction", $rule);

    if ($direction eq 'OUT'){
	# add tap->host rules
	my $rule = "-m physdev --physdev-$physdevdirection $iface -j $tapchain";
	ruleset_addrule($ruleset, "PVEFW-INPUT", $rule);
    }
}

sub enable_host_firewall {
    my ($ruleset, $hostfw_conf, $groups_conf) = @_;

    # fixme: allow security groups

    my $options = $hostfw_conf->{options};
    my $rules = $hostfw_conf->{rules};

    # host inbound firewall
    my $chain = "PVEFW-HOST-IN";
    ruleset_create_chain($ruleset, $chain);

    my $loglevel = get_option_log_level($options, "log_level_in");

    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID -j DROP");
    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-i lo -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-m addrtype --dst-type MULTICAST -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m conntrack --ctstate NEW -m multiport --dports 5404,5405 -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m udp --dport 9000 -j ACCEPT");  #corosync

    # we use RETURN because we need to check also tap rules
    my $accept_action = 'RETURN';

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'in';
	ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" });
    }

    # implement input policy
    my $policy = $options->{'policy-in'} || 'DROP'; # allow nothing by default
    ruleset_add_chain_policy($ruleset, $chain, $policy, $loglevel, $accept_action);

    # host outbound firewall
    $chain = "PVEFW-HOST-OUT";
    ruleset_create_chain($ruleset, $chain);

    $loglevel = get_option_log_level($options, "log_level_out");

    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate INVALID -j DROP");
    ruleset_addrule($ruleset, $chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-o lo -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-m addrtype --dst-type MULTICAST -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m conntrack --ctstate NEW -m multiport --dports 5404,5405 -j ACCEPT");
    ruleset_addrule($ruleset, $chain, "-p udp -m udp --dport 9000 -j ACCEPT"); #corosync

    # we use RETURN because we may want to check other thigs later
    $accept_action = 'RETURN';

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'out';
	ruleset_generate_rule($ruleset, $chain, $rule, { ACCEPT => $accept_action, REJECT => "PVEFW-reject" });
    }

    # implement output policy
    $policy = $options->{'policy-out'} || 'ACCEPT'; # allow everything by default
    ruleset_add_chain_policy($ruleset, $chain, $policy, $loglevel, $accept_action);

    ruleset_addrule($ruleset, "PVEFW-OUTPUT", "-j PVEFW-HOST-OUT");
    ruleset_addrule($ruleset, "PVEFW-INPUT", "-j PVEFW-HOST-IN");
}

sub generate_group_rules {
    my ($ruleset, $groups_conf, $group) = @_;

    die "no such security group '$group'\n" if !$groups_conf->{$group};

    my $rules = $groups_conf->{$group}->{rules};

    my $chain = "GROUP-${group}-IN";

    ruleset_create_chain($ruleset, $chain);

    foreach my $rule (@$rules) {
	next if $rule->{type} ne 'in';
	ruleset_generate_rule($ruleset, $chain, $rule, { REJECT => "PVEFW-reject" });
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

    my $macros = get_firewall_macros();
    my $protocols = get_etc_protocols();

    my ($type, $action, $iface, $source, $dest, $proto, $dport, $sport);

    # we can add single line comments to the end of the rule
    my $comment = $1 if $line =~ s/#\s*(.*?)\s*$//;

    # we can disable a rule when prefixed with '|'
    my $disable = 1 if  $line =~ s/^\|//;

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
    my $macro_name;

    $type = lc($type);

    if ($type eq  'in' || $type eq 'out') {
	if ($action =~ m/^(ACCEPT|DROP|REJECT)$/) {
	    # OK
	} elsif ($action =~ m/^(\S+)\((ACCEPT|DROP|REJECT)\)$/) {
	    ($macro_name, $action) = ($1, $2);
	    my $lc_macro_name = lc($macro_name);
	    my $preferred_name = $pve_fw_preferred_macro_names->{$lc_macro_name};
	    $macro_name = $preferred_name if $preferred_name;
	    $macro = $macros->{$lc_macro_name};
	    die "unknown macro '$macro_name'\n" if !$macro;
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
	die "unknown interface '$iface'\n"
	    if defined($iface) && !$valid_netdev_names->{$iface};
    }

    $proto = undef if $proto && $proto eq '-';
    die "unknown protokol '$proto'\n" if $proto &&
	!(defined($protocols->{byname}->{$proto}) ||
	  defined($protocols->{byid}->{$proto}));

    $source = undef if $source && $source eq '-';
    $dest = undef if $dest && $dest eq '-';

    $dport = undef if $dport && $dport eq '-';
    $sport = undef if $sport && $sport eq '-';

    my $nbsource = undef;
    my $nbdest = undef;

    $nbsource = parse_address_list($source) if $source;
    $nbdest = parse_address_list($dest) if $dest;

    my $rules = [];

    my $param = {
	type => $type,
	disable => $disable,
	comment => $comment,
	action => $action,
	iface => $iface,
	source => $source,
	dest => $dest,
	nbsource => $nbsource,
	nbdest => $nbdest,
	proto => $proto,
	dport => $dport,
	sport => $sport,
    };

    if ($macro) {
	foreach my $templ (@$macro) {
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
    } else {
	push @$rules, $param;
    }

    foreach my $rule (@$rules) {
	$rule->{nbdport} = parse_port_name_number_or_range($rule->{dport})
	    if defined($rule->{dport});
	$rule->{nbsport} = parse_port_name_number_or_range($rule->{sport})
	    if defined($rule->{sport});
    }

    return $rules;
}

sub parse_vmfw_option {
    my ($line) = @_;

    my ($opt, $value);

    my $loglevels = "emerg|alert|crit|err|warning|notice|info|debug|nolog";

    if ($line =~ m/^(enable|dhcp|macfilter|nosmurfs|tcpflags):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(log_level_in|log_level_out):\s*(($loglevels)\s*)?$/i) {
	$opt = lc($1);
	$value = $2 ? lc($3) : '';
    } elsif ($line =~ m/^(policy-(in|out)):\s*(ACCEPT|DROP|REJECT)\s*$/i) {
	$opt = lc($1);
	$value = uc($3);
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

    if ($line =~ m/^(enable|dhcp|nosmurfs|tcpflags):\s*(0|1)\s*$/i) {
	$opt = lc($1);
	$value = int($2);
    } elsif ($line =~ m/^(log_level_in|log_level_out|tcp_flags_log_level|smurf_log_level):\s*(($loglevels)\s*)?$/i) {
	$opt = lc($1);
	$value = $2 ? lc($3) : '';
    } elsif ($line =~ m/^(policy-(in|out)):\s*(ACCEPT|DROP|REJECT)\s*$/i) {
	$opt = lc($1);
	$value = uc($3);
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

    while (defined(my $line = <$fh>)) {
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

	my $rules;
	eval { $rules = parse_fw_rule($line, 1, 1); };
	if (my $err = $@) {
	    warn "$prefix: $err";
	    next;
	}

	push @{$res->{$section}}, @$rules;
    }

    return $res;
}

sub parse_host_fw_rules {
    my ($filename, $fh) = @_;

    my $res = { rules => [], options => {}};

    my $section;

    while (defined(my $line = <$fh>)) {
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

	my $rules;
	eval { $rules = parse_fw_rule($line, 1, 1); };
	if (my $err = $@) {
	    warn "$prefix: $err";
	    next;
	}

	push @{$res->{$section}}, @$rules;
    }

    return $res;
}

sub parse_group_fw_rules {
    my ($filename, $fh) = @_;

    my $section;
    my $group;

    my $res = { rules => [] };

    while (defined(my $line = <$fh>)) {
	next if $line =~ m/^#/;
	next if $line =~ m/^\s*$/;

	my $linenr = $fh->input_line_number();
	my $prefix = "$filename (line $linenr)";

	if ($line =~ m/^\[group\s+(\S+)\]\s*$/i) {
	    $section = 'rules';
	    $group = lc($1);
	    next;
	}
	if (!$section || !$group) {
	    warn "$prefix: skip line - no section";
	    next;
	}

	my $rules;
	eval { $rules = parse_fw_rule($line, 0, 0); };
	if (my $err = $@) {
	    warn "$prefix: $err";
	    next;
	}

	push @{$res->{$group}->{$section}}, @$rules;
    }

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

    my $list = PVE::QemuServer::config_list();

    foreach my $vmid (keys %$list) {
	my $cfspath = PVE::QemuServer::cfs_config_path($vmid);
	if (my $conf = PVE::Cluster::cfs_read_file($cfspath)) {
	    $qemu->{$vmid} = $conf;
	}
    }

    my $vmdata = { openvz => $openvz, qemu => $qemu };

    return $vmdata;
};

sub read_vm_firewall_rules {
    my ($vmdata) = @_;
    my $rules = {};
    foreach my $vmid (keys %{$vmdata->{qemu}}, keys %{$vmdata->{openvz}}) {
	my $filename = "/etc/pve/firewall/$vmid.fw";
	my $fh = IO::File->new($filename, O_RDONLY);
	next if !$fh;

	$rules->{$vmid} = parse_vm_fw_rules($filename, $fh);
    }

    return $rules;
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
    if (defined($loglevel)) {
	$pve_std_chains-> {'PVEFW-smurflog'} = [
	    "-j LOG --log-prefix \"smurfs-dropped\" --log-level $loglevel",
	    "-j DROP",
	    ];
    } else {
	$pve_std_chains-> {'PVEFW-smurflog'} = [ "-j DROP" ];
    }

    # same as shorewall logflags action.
    $loglevel = get_option_log_level($options, 'tcp_flags_log_level');
    if (defined($loglevel)) {
	$pve_std_chains-> {'PVEFW-logflags'} = [
	    "-j LOG --log-prefix \"logflags-dropped:\" --log-level $loglevel --log-ip-options",
	    "-j DROP",
	    ];
    } else {
	$pve_std_chains-> {'PVEFW-logflags'} = [ "-j DROP" ];
    }

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

sub compile {
    my $vmdata = read_local_vm_config();
    my $rules = read_vm_firewall_rules($vmdata);

    my $groups_conf = {};
    my $filename = "/etc/pve/firewall/groups.fw";
    if (my $fh = IO::File->new($filename, O_RDONLY)) {
	$groups_conf = parse_group_fw_rules($filename, $fh);
    }

    #print Dumper($rules);

    my $ruleset = {};

    ruleset_create_chain($ruleset, "PVEFW-INPUT");
    ruleset_create_chain($ruleset, "PVEFW-OUTPUT");
    ruleset_create_chain($ruleset, "PVEFW-FORWARD");

    my $hostfw_options = {};
    my $hostfw_conf;

    $filename = "/etc/pve/local/host.fw";
    if (my $fh = IO::File->new($filename, O_RDONLY)) {
	$hostfw_conf = parse_host_fw_rules($filename, $fh);
	$hostfw_options = $hostfw_conf->{options};
    }

    generate_std_chains($ruleset, $hostfw_options);

    my $hostfw_enable = $hostfw_conf && 
	!(defined($hostfw_options->{enable}) && ($hostfw_options->{enable} == 0));

    enable_host_firewall($ruleset, $hostfw_conf, $groups_conf) if $hostfw_enable;

    # generate firewall rules for QEMU VMs
    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	my $conf = $vmdata->{qemu}->{$vmid};
	my $vmfw_conf = $rules->{$vmid};
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

	    generate_bridge_chains($ruleset, $bridge);

	    my $macaddr = $net->{macaddr};
	    generate_tap_rules_direction($ruleset, $groups_conf, $iface, $netid, $macaddr, $vmfw_conf, $bridge, 'IN');
	    generate_tap_rules_direction($ruleset, $groups_conf, $iface, $netid, $macaddr, $vmfw_conf, $bridge, 'OUT');
	}
    }

    return $ruleset;
}

sub get_ruleset_status {
    my ($ruleset, $verbose) = @_;

    my $active_chains = iptables_get_chains();

    my $statushash = {};

    foreach my $chain (sort keys %$ruleset) {
	my $digest = Digest::SHA->new('sha1');
	foreach my $cmd (@{$ruleset->{$chain}}) {
	     $digest->add("$cmd\n");
	}
	my $sig = $digest->b64digest;
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

sub print_ruleset {
    my ($ruleset) = @_;

    get_ruleset_status($ruleset, 1);
}

sub print_sig_rule {
    my ($chain, $sig) = @_;

    # We just use this to store a SHA1 checksum used to detect changes
    return "-A $chain -m comment --comment \"PVESIG:$sig\"\n";
}

sub get_rulset_cmdlist {
    my ($ruleset, $verbose) = @_;

    my $cmdlist = "*filter\n"; # we pass this to iptables-restore;

    my $statushash = get_ruleset_status($ruleset, $verbose);

    # create missing chains first
    foreach my $chain (sort keys %$ruleset) {
	my $stat = $statushash->{$chain};
	die "internal error" if !$stat;
	next if $stat->{action} ne 'create';

	$cmdlist .= ":$chain - [0:0]\n";
    }

    my $rule = "INPUT -j PVEFW-INPUT";
    if (!PVE::Firewall::iptables_rule_exist($rule)) {
	$cmdlist .= "-A $rule\n";
    }
    $rule = "OUTPUT -j PVEFW-OUTPUT";
    if (!PVE::Firewall::iptables_rule_exist($rule)) {
	$cmdlist .= "-A $rule\n";
    }

    $rule = "FORWARD -j PVEFW-FORWARD";
    if (!PVE::Firewall::iptables_rule_exist($rule)) {
	$cmdlist .= "-A $rule\n";
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

    $cmdlist .= "COMMIT\n";

    return $cmdlist;
}

sub apply_ruleset {
    my ($ruleset, $verbose) = @_;

    enable_bridge_firewall();

    my $cmdlist = get_rulset_cmdlist($ruleset, $verbose);

    print $cmdlist if $verbose;

    iptables_restore_cmdlist($cmdlist);

    # test: re-read status and check if everything is up to date
    my $statushash = get_ruleset_status($ruleset);

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

sub update {
    my ($start, $verbose) = @_;

    my $code = sub {
	my $status = read_pvefw_status();

	my $ruleset = PVE::Firewall::compile();

	if ($start || $status eq 'active') {

	    save_pvefw_status('active')	if ($status ne 'active');

	    PVE::Firewall::apply_ruleset($ruleset, $verbose);
	} else {
	    print "Firewall not active (status = $status)\n" if $verbose;
	}
    };

    run_locked($code);
}


1;
