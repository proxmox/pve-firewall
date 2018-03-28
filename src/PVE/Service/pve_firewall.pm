package PVE::Service::pve_firewall;

use strict;
use warnings;
use PVE::SafeSyslog;
use PVE::Daemon;

use Time::HiRes qw (gettimeofday);
use PVE::Tools qw(dir_glob_foreach file_read_firstline);
use PVE::ProcFSTools;
use PVE::INotify;
use PVE::Cluster qw(cfs_read_file);
use PVE::RPCEnvironment;
use PVE::CLIHandler;
use PVE::Firewall;
use PVE::FirewallSimulator;
use Data::Dumper;

use base qw(PVE::Daemon);

my $cmdline = [$0, @ARGV];

my %daemon_options = (restart_on_error => 5, stop_wait_time => 5);

my $daemon = __PACKAGE__->new('pve-firewall', $cmdline, %daemon_options);

my $nodename = PVE::INotify::nodename();

sub init {

    PVE::Cluster::cfs_update();
    
    PVE::Firewall::init();
}

my $restart_request = 0;
my $next_update = 0;

my $cycle = 0; 
my $updatetime = 10;

my $initial_memory_usage;

sub shutdown {
    my ($self) = @_;

    syslog('info' , "server closing");

    # wait for children
    1 while (waitpid(-1, POSIX::WNOHANG()) > 0);
	
    syslog('info' , "clear firewall rules");

    eval { PVE::Firewall::remove_pvefw_chains(); };
    warn $@ if $@;

    $self->exit_daemon(0);
}

sub hup {
    my ($self) = @_;

    $restart_request = 1;
}

sub run {
    my ($self) = @_;

    local $SIG{'__WARN__'} = 'IGNORE'; # do not fill up logs

    for (;;) { # forever

	$next_update = time() + $updatetime;

	my ($ccsec, $cusec) = gettimeofday ();
	eval {
	    PVE::Cluster::cfs_update();
	    PVE::Firewall::update();
	};
	my $err = $@;
	
	if ($err) {
	    syslog('err', "status update error: $err");
	}

	my ($ccsec_end, $cusec_end) = gettimeofday ();
	my $cptime = ($ccsec_end-$ccsec) + ($cusec_end - $cusec)/1000000;

	syslog('info', sprintf("firewall update time (%.3f seconds)", $cptime))
	    if ($cptime > 5);

	$cycle++;

	my $mem = PVE::ProcFSTools::read_memory_usage();
	
	if (!defined($initial_memory_usage) || ($cycle < 10)) {
	    $initial_memory_usage = $mem->{resident};
	} else {
	    my $diff = $mem->{resident} - $initial_memory_usage;
	    if ($diff > 5*1024*1024) {
		syslog ('info', "restarting server after $cycle cycles to " .
			"reduce memory usage (free $mem->{resident} ($diff) bytes)");
		$self->restart_daemon();
	    }
	}

	my $wcount = 0;
	while ((time() < $next_update) && 
	       ($wcount < $updatetime) && # protect against time wrap
	       !$restart_request) { $wcount++; sleep (1); };
	
	$self->restart_daemon() if $restart_request;
    }
}

$daemon->register_start_command("Start the Proxmox VE firewall service.");
$daemon->register_restart_command(1, "Restart the Proxmox VE firewall service.");
$daemon->register_stop_command("Stop firewall. This removes all Proxmox VE " .
			       "related iptable rules. " .
			       "The host is unprotected afterwards.");

__PACKAGE__->register_method ({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Get firewall status.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => { 
	type => 'object',
	additionalProperties => 0,
	properties => {
	    status => {
		type => 'string',
		enum => ['unknown', 'stopped', 'running'],
	    },
	    enable => {
		description => "Firewall is enabled (in 'cluster.fw')",
		type => 'boolean',
	    },
	    changes => {
		description => "Set when there are pending changes.",
		type => 'boolean',
		optional => 1,
	    }
	},
    },
    code => sub {
	my ($param) = @_;

	local $SIG{'__WARN__'} = 'DEFAULT'; # do not fill up syslog

	my $code = sub {

	    my $status = $daemon->running() ? 'running' : 'stopped';

	    my $res = { status => $status };

	    my $verbose = 1; # show syntax errors 
	    my $cluster_conf = PVE::Firewall::load_clusterfw_conf(undef, $verbose); 
	    $res->{enable} = $cluster_conf->{options}->{enable} ? 1 : 0;

	    if ($status eq 'running') {
		
		my ($ruleset, $ipset_ruleset, $rulesetv6, $ebtables_ruleset) = PVE::Firewall::compile($cluster_conf, undef, undef, $verbose);

		$verbose = 0; # do not show iptables details
		my (undef, undef, $ipset_changes) = PVE::Firewall::get_ipset_cmdlist($ipset_ruleset, $verbose);
		my ($test, $ruleset_changes) = PVE::Firewall::get_ruleset_cmdlist($ruleset, $verbose);
		my (undef, $ruleset_changesv6) = PVE::Firewall::get_ruleset_cmdlist($rulesetv6, $verbose, "ip6tables");
+		my (undef, $ebtables_changes) = PVE::Firewall::get_ebtables_cmdlist($ebtables_ruleset, $verbose);

		$res->{changes} = ($ipset_changes || $ruleset_changes || $ruleset_changesv6 || $ebtables_changes) ? 1 : 0;
	    }

	    return $res;
	};

	return PVE::Firewall::run_locked($code);
    }});

__PACKAGE__->register_method ({
    name => 'compile',
    path => 'compile',
    method => 'GET',
    description => "Compile and print firewall rules. This is useful for testing.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },

    code => sub {
	my ($param) = @_;

	local $SIG{'__WARN__'} = 'DEFAULT'; # do not fill up syslog

	my $code = sub {

	    my $verbose = 1;

	    my $cluster_conf = PVE::Firewall::load_clusterfw_conf(undef, $verbose); 
	    my ($ruleset, $ipset_ruleset, $rulesetv6, $ebtables_ruleset) = PVE::Firewall::compile($cluster_conf, undef, undef, $verbose);

	    print "ipset cmdlist:\n";
	    my (undef, undef, $ipset_changes) = PVE::Firewall::get_ipset_cmdlist($ipset_ruleset, $verbose);

	    print "\niptables cmdlist:\n";
	    my (undef, $ruleset_changes) = PVE::Firewall::get_ruleset_cmdlist($ruleset, $verbose);

	    print "\nip6tables cmdlist:\n";
	    my (undef, $ruleset_changesv6) = PVE::Firewall::get_ruleset_cmdlist($rulesetv6, $verbose, "ip6tables");

	    print "\nebtables cmdlist:\n";
	    my (undef, $ebtables_changes) = PVE::Firewall::get_ebtables_cmdlist($ebtables_ruleset, $verbose);

	    if ($ipset_changes || $ruleset_changes || $ruleset_changesv6 || $ebtables_changes) {
		print "detected changes\n";
	    } else {
		print "no changes\n";
	    }
	    if (!$cluster_conf->{options}->{enable}) {
		print "firewall disabled\n";
	    }

	};

	PVE::Firewall::run_locked($code);

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'localnet',
    path => 'localnet',
    method => 'GET',
    description => "Print information about local network.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	local $SIG{'__WARN__'} = 'DEFAULT'; # do not fill up syslog

	my $nodename = PVE::INotify::nodename();
	print "local hostname: $nodename\n";

	my $ip = PVE::Cluster::remote_node_ip($nodename);
	print "local IP address: $ip\n";

	my $cluster_conf = PVE::Firewall::load_clusterfw_conf();
	
	my $localnet = PVE::Firewall::local_network() || '127.0.0.0/8';
	print "network auto detect: $localnet\n";
	if ($cluster_conf->{aliases}->{local_network}) {
	    print "using user defined local_network: $cluster_conf->{aliases}->{local_network}->{cidr}\n";
	} else {
	    print "using detected local_network: $localnet\n";
	}

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'simulate',
    path => 'simulate',
    method => 'GET',
    description => "Simulate firewall rules. This does not simulate kernel 'routing' table. Instead, this simply assumes that routing from source zone to destination zone is possible.",
    parameters => {
    	additionalProperties => 0,
	properties => {
	    verbose => {
		description => "Verbose output.",
		type => 'boolean',
		optional => 1,
		default => 0,
	    },
	    from => {
		description => "Source zone.",
		type => 'string',
		pattern => '(host|outside|vm\d+|ct\d+|vmbr\d+/\S+)',
		optional => 1,
		default => 'outside',
	    },
	    to => {
		description => "Destination zone.",
		type => 'string',
		pattern => '(host|outside|vm\d+|ct\d+|vmbr\d+/\S+)',
		optional => 1,
		default => 'host',
	    },
	    protocol => {
		description => "Protocol.",
		type => 'string',
		pattern => '(tcp|udp)',
		optional => 1,
		default => 'tcp',
	    },
	    dport => {
		description => "Destination port.",
		type => 'integer',
		minValue => 1,
		maxValue => 65535,
		optional => 1,
	    },
	    sport => {
		description => "Source port.",
		type => 'integer',
		minValue => 1,
		maxValue => 65535,
		optional => 1,
	    },
	    source => {
		description => "Source IP address.",
		type => 'string', format => 'ipv4',
		optional => 1,
	    },
	    dest => {
		description => "Destination IP address.",
		type => 'string', format => 'ipv4',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	local $SIG{'__WARN__'} = 'DEFAULT'; # do not fill up syslog

	my ($ruleset, $ipset_ruleset, $rulesetv6, $ebtables_ruleset) = PVE::Firewall::compile(undef, undef, undef, $param->{verbose});

	PVE::FirewallSimulator::debug($param->{verbose} || 0);
	
	my $host_ip = PVE::Cluster::remote_node_ip($nodename);

	PVE::FirewallSimulator::reset_trace();
	print Dumper($ruleset) if $param->{verbose};

	my $test = {
	    from => $param->{from},
	    to => $param->{to},
	    proto => $param->{protocol} || 'tcp',
	    source => $param->{source},
	    dest => $param->{dest},
	    dport => $param->{dport},
	    sport => $param->{sport},
	};

	if (!defined($test->{to})) {
	    $test->{to} = 'host';
	    PVE::FirewallSimulator::add_trace("Set Zone: to => '$test->{to}'\n"); 
	} 
	if (!defined($test->{from})) {
	    $test->{from} = 'outside',
	    PVE::FirewallSimulator::add_trace("Set Zone: from => '$test->{from}'\n"); 
	}

	my $vmdata = PVE::Firewall::read_local_vm_config();

	print "Test packet:\n";

	foreach my $k (qw(from to proto source dest dport sport)) {
	    printf("  %-8s: %s\n", $k, $test->{$k}) if defined($test->{$k});
	}

	$test->{action} = 'QUERY';

	my $res = PVE::FirewallSimulator::simulate_firewall($ruleset, $ipset_ruleset, 
							    $host_ip, $vmdata, $test);
	
	print "ACTION: $res\n";

	return undef;
    }});

our $cmddef = {
    start => [ __PACKAGE__, 'start', []],
    restart => [ __PACKAGE__, 'restart', []],
    stop => [ __PACKAGE__, 'stop', []],
    compile => [ __PACKAGE__, 'compile', []],
    simulate => [ __PACKAGE__, 'simulate', []],
    localnet => [ __PACKAGE__, 'localnet', []],
    status => [ __PACKAGE__, 'status', [], undef, sub {
	my $res = shift;
	my $status = ($res->{enable} ? "enabled" : "disabled") . '/' . $res->{status};
	
	if ($res->{changes}) {
	    print "Status: $status (pending changes)\n";
	} else {
	    print "Status: $status\n";
	}
    }],
 };

1;
