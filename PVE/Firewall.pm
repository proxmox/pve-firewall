package PVE::Firewall;

use warnings;
use strict;
use Data::Dumper;
use PVE::Tools;
use PVE::QemuServer;
use File::Path;
use IO::File;
use Net::IP;
use PVE::Tools qw(run_command);

use Data::Dumper;

my $macros;
my @ruleset = ();

sub get_shorewall_macros {

    return $macros if $macros;

    foreach my $path (</usr/share/shorewall/macro.*>) {
	if ($path =~ m|/macro\.(\S+)$|) {
	    $macros->{$1} = 1;
	}
    }
    return $macros;
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

    foreach my $aor (split(/,/, $str)) {
	if (!Net::IP->new($aor)) {
	    my $err = Net::IP::Error();
	    die "invalid IP address: $err\n";
	}
    }
}

sub parse_port_name_number_or_range {
    my ($str) = @_;

    my $services = PVE::Firewall::get_etc_services();

    foreach my $item (split(/,/, $str)) {
	foreach my $pon (split(':', $item, 2)) {
	    next if $pon =~ m/^\d+$/ && $pon > 0 && $pon < 65536;
	    next if defined($services->{byname}->{$pon});
	    die "invalid port '$pon'\n";
	}
    }

}

my $rule_format = "%-15s %-30s %-30s %-15s %-15s %-15s\n";

sub iptables {
    my ($cmd) = @_;

    run_command("/sbin/iptables $cmd", outfunc => sub {}, errfunc => sub {});
}

sub iptables_restore {

    unshift (@ruleset, '*filter');
    push (@ruleset, 'COMMIT');

    my $cmdlist = join("\n", @ruleset);

    run_command("echo '$cmdlist' | /sbin/iptables-restore -n", outfunc => sub {});
}

sub iptables_addrule {
   my ($rule) = @_;

   push (@ruleset, $rule);
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

sub iptables_generate_rule {
    my ($chain, $rule) = @_;

    my $cmd = "-A $chain";

    $cmd .= " -s $rule->{source}" if $rule->{source};
    $cmd .= " -d $rule->{dest}" if $rule->{destination};
    $cmd .= " -p $rule->{proto}" if $rule->{proto};
    $cmd .= " --dport $rule->{dport}" if $rule->{dport};
    $cmd .= " --sport $rule->{sport}" if $rule->{sport};
    $cmd .= " -j $rule->{action}" if $rule->{action};

    iptables_addrule($cmd);

}

sub generate_bridge_rules {
    my ($bridge) = @_;

    if(!iptables_chain_exist("BRIDGEFW-OUT")){
	iptables_addrule(":BRIDGEFW-OUT - [0:0]");
    }

    if(!iptables_chain_exist("BRIDGEFW-IN")){
	iptables_addrule(":BRIDGEFW-IN - [0:0]");
    }

    if(!iptables_chain_exist("proxmoxfw-FORWARD")){
	iptables_addrule(":proxmoxfw-FORWARD - [0:0]");
	iptables_addrule("-I FORWARD -j proxmoxfw-FORWARD");
	iptables_addrule("-A proxmoxfw-FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT");
	iptables_addrule("-A proxmoxfw-FORWARD -m physdev --physdev-is-in --physdev-is-bridged -j BRIDGEFW-OUT");
	iptables_addrule("-A proxmoxfw-FORWARD -m physdev --physdev-is-out --physdev-is-bridged -j BRIDGEFW-IN");

    }

    generate_proxmoxfwinput();

    if(!iptables_chain_exist("$bridge-IN")){
	iptables_addrule(":$bridge-IN - [0:0]");
	iptables_addrule("-A proxmoxfw-FORWARD -i $bridge -j DROP");  #disable interbridge routing
	iptables_addrule("-A BRIDGEFW-IN -j $bridge-IN");
	iptables_addrule("-A $bridge-IN -j ACCEPT");

    }

    if(!iptables_chain_exist("$bridge-OUT")){
	iptables_addrule(":$bridge-OUT - [0:0]");
	iptables_addrule("-A proxmoxfw-FORWARD -o $bridge -j DROP"); # disable interbridge routing
	iptables_addrule("-A BRIDGEFW-OUT -j $bridge-OUT");

    }

}


sub generate_tap_rules_direction {
    my ($iface, $netid, $rules, $bridge, $direction) = @_;

    my $tapchain = "$iface-$direction";

    iptables_addrule(":$tapchain - [0:0]");

    iptables_addrule("-A $tapchain -m state --state INVALID -j DROP");
    iptables_addrule("-A $tapchain -m state --state RELATED,ESTABLISHED -j ACCEPT");

    if (scalar(@$rules)) {
        foreach my $rule (@$rules) {
	    next if $rule->{iface} && $rule->{iface} ne $netid;
	    if($rule->{action}  =~ m/^(GROUP-(\S+))$/){
		    $rule->{action} .= "-$direction";
		    #generate empty group rule if don't exist
		    if(!iptables_chain_exist($rule->{action})){
			generate_group_rules($2);
		    }
	    }
	    #we go to vmbr-IN if accept in out rules
	    $rule->{action} = "$bridge-IN" if $rule->{action} eq 'ACCEPT' && $direction eq 'OUT';
	    iptables_generate_rule($tapchain, $rule);
        }
    }

    iptables_addrule("-A $tapchain -j LOG --log-prefix \"$tapchain-dropped: \" --log-level 4");
    iptables_addrule("-A $tapchain -j DROP");

    #plug the tap chain to bridge chain
    my $physdevdirection = $direction eq 'IN' ? "out":"in";
    my $rule = "$bridge-$direction -m physdev --physdev-$physdevdirection $iface --physdev-is-bridged -j $tapchain";

    if(!iptables_rule_exist($rule)){
	iptables_addrule("-I $rule");
    }

    if($direction eq 'OUT'){
	#add tap->host rules
	my $rule = "proxmoxfw-INPUT -m physdev --physdev-$physdevdirection $iface -j $tapchain";

	if(!iptables_rule_exist($rule)){
	    iptables_addrule("-A $rule");
	}
    }
}

sub generate_tap_rules {
    my ($net, $netid, $vmid) = @_;

    my $filename = "/etc/pve/firewall/$vmid.fw";
    my $fh = IO::File->new($filename, O_RDONLY);
    return if !$fh;

    #generate bridge rules
    my $bridge = $net->{bridge};
    my $tag = $net->{tag};
    $bridge .= "v$tag" if $tag;
   
    #generate tap chain
    my $rules = parse_fw_rules($filename, $fh);

    my $inrules = $rules->{in};
    my $outrules = $rules->{out};

    my $iface = "tap".$vmid."i".$1 if $netid =~ m/net(\d+)/;

    generate_bridge_rules($bridge);
    generate_tap_rules_direction($iface, $netid, $inrules, $bridge, 'IN');
    generate_tap_rules_direction($iface, $netid, $outrules, $bridge, 'OUT');
    iptables_restore();
}

sub flush_tap_rules {
    my ($net, $netid, $vmid) = @_;

    my $bridge = $net->{bridge};
    my $iface = "tap".$vmid."i".$1 if $netid =~ m/net(\d+)/;

    flush_tap_rules_direction($iface, $bridge, 'IN');
    flush_tap_rules_direction($iface, $bridge, 'OUT');
    iptables_restore();
}

sub flush_tap_rules_direction {
    my ($iface, $bridge, $direction) = @_;

    my $tapchain = "$iface-$direction";

    if(iptables_chain_exist($tapchain)){
	iptables_addrule("-F $tapchain");

	my $physdevdirection = $direction eq 'IN' ? "out":"in";
	my $rule = "$bridge-$direction -m physdev --physdev-$physdevdirection $iface --physdev-is-bridged -j $tapchain";
	if(iptables_rule_exist($rule)){
	    iptables_addrule("-D $rule");
	}

	if($direction eq 'OUT'){
	    my $rule = "proxmoxfw-INPUT -m physdev --physdev-$physdevdirection $iface -j $tapchain";

	    if(!iptables_rule_exist($rule)){
		iptables_addrule("-D $rule");
	    }
	}

	iptables_addrule("-X $tapchain");
    }
}

my $generate_input_rule = sub {
    my ($zoneinfo, $rule, $net, $netid) = @_;

    my $zone = $net->{zone} || die "internal error";
    my $zid = $zoneinfo->{$zone}->{zoneref} || die "internal error";
    my $tap = $net->{tap} || die "internal error";

    my $dest = "$zid:$tap";

    if ($rule->{dest}) {
	$dest .= ":$rule->{dest}";
    }

    my $action = $rule->{service} ? 
	"$rule->{service}($rule->{action})" : $rule->{action};

    my $sources = [];

    if (!$rule->{source}) {
	push @$sources, 'all'; 
    } elsif ($zoneinfo->{$zone}->{type} eq 'bport') {
	my $bridge_zone = $zoneinfo->{$zone}->{bridge_zone} || die "internal error";
	my $zoneref = $zoneinfo->{$bridge_zone}->{zoneref} || die "internal error";

	# using 'all' does not work, so we create one rule for
	# each related zone on the same bridge
	push @$sources, "${zoneref}:$rule->{source}";
	foreach my $z (keys %$zoneinfo) {
	    next if $z eq $zone;
	    next if !$zoneinfo->{$z}->{bridge_zone};
	    next if $zoneinfo->{$z}->{bridge_zone} ne $bridge_zone;
	    $zoneref = $zoneinfo->{$z}->{zoneref} || die "internal error";
	    push @$sources, "${zoneref}:$rule->{source}";
	}
    } else {
	push @$sources, "all:$rule->{source}";
    }

    my $out = '';

    foreach my $source (@$sources) {
	$out .= sprintf($rule_format, $action, $source, $dest, $rule->{proto} || '-', 
			$rule->{dport} || '-', $rule->{sport} || '-');
    }

    return $out;
};

my $generate_output_rule = sub {
    my ($zoneinfo, $rule, $net, $netid) = @_;

    my $zone = $net->{zone} || die "internal error";
    my $zid = $zoneinfo->{$zone}->{zoneref} || die "internal error";
    my $tap = $net->{tap} || die "internal error";

    my $action = $rule->{service} ? 
	"$rule->{service}($rule->{action})" : $rule->{action};
    
    my $dest;

    if (!$rule->{dest}) {
	$dest = 'all';
    } else {
	$dest = "all:$rule->{dest}";
    }

    return sprintf($rule_format, $action, "$zid:$tap", $dest, 
		   $rule->{proto} || '-', $rule->{dport} || '-', $rule->{sport} || '-');
};

# we need complete VM configuration of all VMs (openvz/qemu)
# in vmdata

my $compile_shorewall = sub {
    my ($targetdir, $vmdata, $rules) = @_;

    # remove existing data ?
    foreach my $file (qw(params zones rules interfaces  maclist  policy)) {
	unlink "$targetdir/$file";
    }

    my $netinfo;

    my $zoneinfo = {
	fw => { type => 'firewall' },
    };

    my $maclist = {};

    my $register_bridge;

    $register_bridge = sub {
	my ($bridge, $vlan) = @_;

	my $zone =  $bridge;

	return $zone if $zoneinfo->{$zone};

	my $ext_zone = "${bridge}_ext";

	$zoneinfo->{$zone} = {
	    type => 'bridge',
	    bridge => $bridge,
	    bridge_ext_zone => $ext_zone,
	};

	# physical input devices
	my $dir = "/sys/class/net/$bridge/brif";
	my $physical = {};
	PVE::Tools::dir_glob_foreach($dir, '((eth|bond).+)', sub {
	    my ($slave) = @_;
	    $physical->{$slave} = 1;
	});

	$zoneinfo->{$ext_zone} = {
	    type => 'bport',
	    bridge_zone => $zone,
	    ifaces => $physical,
	};

	return &$register_bridge("${bridge}v${vlan}") if defined($vlan);
	
	return $zone;
    };

    my $register_bridge_port = sub {
	my ($bridge, $vlan, $vmzone, $tap) = @_;

	my $bridge_zone = &$register_bridge($bridge, $vlan);
	my $zone = $bridge_zone . '_' . $vmzone;

	if (!$zoneinfo->{$zone}) {
	    $zoneinfo->{$zone} = {
		type => 'bport',
		bridge_zone => $bridge_zone,
		ifaces => {},
	    };
	}

	$zoneinfo->{$zone}->{ifaces}->{$tap} = 1;
	
	return $zone;
    };

    foreach my $vmid (keys %{$vmdata->{qemu}}) {
	$netinfo->{$vmid} = {};
	my $conf = $vmdata->{qemu}->{$vmid};
	foreach my $opt (keys %$conf) {
	    next if $opt !~ m/^net(\d+)$/;
	    my $netnum = $1;
	    my $net = PVE::QemuServer::parse_net($conf->{$opt});
	    next if !$net;
	    die "implement me" if !$net->{bridge};

	    my $vmzone = $conf->{zone} || "vm$vmid";
	    $net->{tap} = "tap${vmid}i${netnum}";
	    $maclist->{$net->{tap}} = $net->{macaddr} || die "internal error";
	    $net->{zone} = &$register_bridge_port($net->{bridge}, $net->{tag}, $vmzone, $net->{tap});
	    $netinfo->{$vmid}->{$opt} = $net;
	}
    }

    #print Dumper($netinfo);

    # NOTE: zone names have length limit, so we need to
    # translate them into shorter names 

    my $zoneid = 0;
    my $zonemap = { fw => 'fw' };

    my $lookup_zonename = sub {
	my ($zone) = @_;

	return $zonemap->{$zone} if defined($zonemap->{$zone});
	$zonemap->{$zone} = 'z' . $zoneid++;

	return $zonemap->{$zone};
    };

    foreach my $z (sort keys %$zoneinfo) {
	$zoneinfo->{$z}->{id} = &$lookup_zonename($z);
	$zoneinfo->{$z}->{zonevar} = uc($z);
 	$zoneinfo->{$z}->{zoneref} = '$' . $zoneinfo->{$z}->{zonevar};
    }

    my $out;

    # dump params file
    $out = "# PVE zones\n";
    foreach my $z (sort keys %$zoneinfo) {
	$out .= "$zoneinfo->{$z}->{zonevar}=$zoneinfo->{$z}->{id}\n";
    }
    PVE::Tools::file_set_contents("$targetdir/params", $out);

    # dump zone file

    my $format = "%-30s %-10s %-15s\n";
    $out = sprintf($format, '#ZONE', 'TYPE', 'OPTIONS');
    
    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{zoneref};
	if ($zoneinfo->{$z}->{type} eq 'firewall') {
	    $out .= sprintf($format, $zid, $zoneinfo->{$z}->{type}, '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bridge') {
	    $out .= sprintf($format, $zid, 'ipv4', '');
	} elsif ($zoneinfo->{$z}->{type} eq 'bport') {
	    my $bridge_zone = $zoneinfo->{$z}->{bridge_zone} || die "internal error";
	    my $bzid = $zoneinfo->{$bridge_zone}->{zoneref} || die "internal error";
	    $out .= sprintf($format, "$zid:$bzid", 'bport', '');
	} else {
	    die "internal error";
	}
    }

    $out .= sprintf("#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n");

    PVE::Tools::file_set_contents("$targetdir/zones", $out);

    # dump interfaces

    $format = "%-25s %-20s %-10s %-15s\n";
    $out = sprintf($format, '#ZONE', 'INTERFACE', 'BROADCAST', 'OPTIONS');

    my $maclist_format = "%-15s %-15s %-15s\n";
    my $macs = sprintf($maclist_format, '#DISPOSITION', 'INTERFACE', 'MACZONE');

    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{zoneref};
	if ($zoneinfo->{$z}->{type} eq 'firewall') {
	    # do nothing;
	} elsif ($zoneinfo->{$z}->{type} eq 'bridge') {
	    my $bridge = $zoneinfo->{$z}->{bridge} || die "internal error";
	    $out .= sprintf($format, $zid, $bridge, 'detect', 'bridge,optional');
	} elsif ($zoneinfo->{$z}->{type} eq 'bport') {
	    my $ifaces = $zoneinfo->{$z}->{ifaces};
	    foreach my $iface (sort keys %$ifaces) {
		my $bridge_zone = $zoneinfo->{$z}->{bridge_zone} || die "internal error";
		my $bridge = $zoneinfo->{$bridge_zone}->{bridge} || die "internal error";
		my $iftxt = "$bridge:$iface";

		if ($maclist->{$iface}) {
		    $out .= sprintf($format, $zid, $iftxt, '-', 'maclist');
		    $macs .= sprintf($maclist_format, 'ACCEPT', $iface, $maclist->{$iface});
		} else {
		    $out .= sprintf($format, $zid, $iftxt, '-', '');
		}
	    }
	} else {
	    die "internal error";
	}
    }

    $out .= sprintf("#LAST LINE - ADD YOUR ENTRIES ABOVE THIS ONE - DO NOT REMOVE\n");

    PVE::Tools::file_set_contents("$targetdir/interfaces", $out);

    # dump maclist
    PVE::Tools::file_set_contents("$targetdir/maclist", $macs);

    # dump policy

    $format = "%-15s %-15s %-15s %s\n";
    $out = sprintf($format, '#SOURCE', 'DEST', 'POLICY', 'LOG');
    $out .= sprintf($format, 'fw', 'all', 'ACCEPT', '');

    # we need to disable intra-zone traffic on bridges. Else traffic
    # from untracked interfaces simply pass the firewall
    foreach my $z (sort keys %$zoneinfo) {
	my $zid = $zoneinfo->{$z}->{zoneref};
	if ($zoneinfo->{$z}->{type} eq 'bridge') {
	    $out .= sprintf($format, $zid, $zid, 'REJECT', 'info');
	}
    }
    $out .= sprintf($format, 'all', 'all', 'REJECT', 'info');

    PVE::Tools::file_set_contents("$targetdir/policy", $out);

    # dump rules
    $out = '';

    $out = sprintf($rule_format, '#ACTION', 'SOURCE', 'DEST', 'PROTO', 'DPORT', 'SPORT');
    foreach my $vmid (sort keys %$rules) {
	my $inrules = $rules->{$vmid}->{in};
	my $outrules = $rules->{$vmid}->{out};

	if (scalar(@$inrules)) {
	    $out .= "# IN to VM $vmid\n";
	    foreach my $rule (@$inrules) {
		foreach my $netid (keys %{$netinfo->{$vmid}}) {
		    my $net = $netinfo->{$vmid}->{$netid};
		    next if $rule->{iface} && $rule->{iface} ne $netid;
		    $out .= &$generate_input_rule($zoneinfo, $rule, $net, $netid);
		}
	    }
	}

	if (scalar(@$outrules)) {
	    $out .= "# OUT from VM $vmid\n";
	    foreach my $rule (@$outrules) {
		foreach my $netid (keys %{$netinfo->{$vmid}}) {
		    my $net = $netinfo->{$vmid}->{$netid};
		    next if $rule->{iface} && $rule->{iface} ne $netid;
		    $out .= &$generate_output_rule($zoneinfo, $rule, $net, $netid);
		}
	    }
	}
    }

    PVE::Tools::file_set_contents("$targetdir/rules", $out);
};


sub parse_fw_rules {
    my ($filename, $fh) = @_;

    my $section;

    my $res = { in => [], out => [] };

    my $macros = get_shorewall_macros();
    my $protocols = get_etc_protocols();
    
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

	if (!$action) {
	    warn "skip incomplete line\n";
	    next;
	}

	my $service;
	if ($action =~ m/^(ACCEPT|DROP|REJECT|GROUP-(\S+))$/) {
	    # OK
	} elsif ($action =~ m/^(\S+)\((ACCEPT|DROP|REJECT)\)$/) {
	    ($service, $action) = ($1, $2);
	    if (!$macros->{$service}) {
		warn "unknown service '$service'\n";
		next;
	    }
	} else {
	    warn "unknown action '$action'\n";
	    next;
	}

	$iface = undef if $iface && $iface eq '-';
	if ($iface && $iface !~ m/^(net0|net1|net2|net3|net4|net5)$/) {
	    warn "unknown interface '$iface'\n";
	    next;
	}

	$proto = undef if $proto && $proto eq '-';
	if ($proto && !(defined($protocols->{byname}->{$proto}) ||
			defined($protocols->{byid}->{$proto}))) {
	    warn "unknown protokol '$proto'\n";
	    next;
	}

	$source = undef if $source && $source eq '-';
	$dest = undef if $dest && $dest eq '-';

	$dport = undef if $dport && $dport eq '-';
	$sport = undef if $sport && $sport eq '-';

	eval {
	    parse_address_list($source) if $source;
	    parse_address_list($dest) if $dest;
	    parse_port_name_number_or_range($dport) if $dport;
	    parse_port_name_number_or_range($sport) if $sport;
	};
	if (my $err = $@) {
	    warn $err;
	    next;

	}


	my $rule = {
	    action => $action,
	    service => $service,
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

sub read_local_vm_config {

    my $openvz = {};

    my $qemu = {};

    my $list = PVE::QemuServer::config_list();

    foreach my $vmid (keys %$list) {
	#next if !($vmid eq '100' || $vmid eq '102');
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

	$rules->{$vmid} = parse_fw_rules($filename, $fh);
    }

    return $rules;
}

sub compile {

    my $vmdata = read_local_vm_config();
    my $rules = read_vm_firewall_rules($vmdata);

    # print Dumper($vmdata);

    my $swdir = '/etc/shorewall';
    mkdir $swdir;

    &$compile_shorewall($swdir, $vmdata, $rules);

    PVE::Tools::run_command(['shorewall', 'compile']);
}

sub compile_and_start {
    my ($restart) = @_;

    compile();

    PVE::Tools::run_command(['shorewall', $restart ? 'restart' : 'start']);
}


1;
