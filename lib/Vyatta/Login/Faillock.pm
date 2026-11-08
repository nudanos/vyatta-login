# SPDX-License-Identifier: LGPL-2.1-only
package Vyatta::Login::Faillock;

use strict;
use warnings;

use Exporter 'import';
use File::Temp qw(tempfile);
use IPC::Run3;

our @EXPORT_OK = qw(validate_lockout configure_lockout migrate_legacy reset_tally tally_counts);

my $profile_dir = '/usr/share/pam-configs';
my $common_auth = '/etc/pam.d/common-auth';
my $pam_update = '/usr/sbin/pam-auth-update';
my $faillock = '/usr/sbin/faillock';
my $tally_dir = '/run/vyatta-faillock';
my $legacy = 'vyatta-pam-tally';
my $failure = 'vyatta-faillock-authfail';
my $success = 'vyatta-faillock-authsucc';

sub _read_file {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "Cannot read $path: $!\n";
    local $/;
    return <$fh> // '';
}

sub _write_profile {
    my ($name, $contents) = @_;
    my $path = "$profile_dir/$name";
    if (!defined($contents)) {
        if (-e $path || -l $path) {
            unlink($path) or die "Cannot remove $path: $!\n";
        }
        return;
    }
    my ($fh, $tmp) = tempfile('vyatta-XXXXXX', DIR => $profile_dir, SUFFIX => '~', UNLINK => 1);
    chmod(0644, $tmp) or die "Cannot set permissions on $tmp: $!\n";
    print {$fh} $contents or die "Cannot write $tmp: $!\n";
    close($fh) or die "Cannot close $tmp: $!\n";
    rename($tmp, $path) or die "Cannot install $path: $!\n";
}

sub _auth_rules {
    my ($stack) = @_;
    my @rules;
    for (split(/\n/, $stack)) {
        s/\s*#.*$//;
        s/^\s+|\s+$//g;
        s/\s+/ /g;
        push @rules, $_ if length($_);
    }
    return @rules;
}

sub _local_auth_stack {
    my ($stack, $expected_options) = @_;
    my @rules = _auth_rules($stack);
    # Debian's optional capabilities profile follows the managed stack.
    pop @rules if @rules && $rules[-1] =~ /^auth optional pam_cap\.so(?: |$)/;

    # The old generated profile was a Primary rule before pam_unix.
    # Accept only its exact form, and only with the matching owned profile.
    if (@rules == 4 && $rules[0] =~ /^auth required pam_tally\.so onerr=fail deny=([0-9]+) unlock_time=([0-9]+)$/) {
        my ($attempts, $seconds) = ($1, $2);
        my $path = "$profile_dir/$legacy";
        return 0 if -l $path || !-f $path;
        my $profile = _read_file($path);
        return 0 unless $profile =~ /^Name: Vyatta pam tally\s*$/m
            && $profile =~ /^\s+required pam_tally\.so onerr=fail deny=\Q$attempts\E unlock_time=\Q$seconds\E\s*$/m;
        shift @rules;
    }
    my $has_lockout = grep { /pam_faillock\.so/ } @rules;
    my ($unix, $deny, $permit) = @rules;
    if ($has_lockout) {
        return 0 unless @rules == 5;
        ($unix, my $fail, $deny, $permit, my $succeed) = @rules;
        return 0 unless $fail =~ /^auth \[default=die\] pam_faillock\.so authfail (.+)$/;
        my $options = $1;
        return 0 unless $options =~ m{^conf=/dev/null dir=\Q$tally_dir\E silent local_users_only deny=[0-9]+ unlock_time=[0-9]+$};
        return 0 if defined($expected_options) && $options ne $expected_options;
        return 0 unless $succeed eq "auth required pam_faillock.so authsucc $options";
    } else {
        return 0 unless @rules == 3 && !defined($expected_options);
    }

    my $jump = $has_lockout ? 2 : 1;
    return $unix =~ /^auth \[success=$jump default=ignore\] pam_unix\.so(?: |$)/
        && $deny eq 'auth requisite pam_deny.so'
        && $permit eq 'auth required pam_permit.so';
}

sub validate_lockout {
    my ($attempts, $seconds, $config, $chain) = @_;
    return unless defined($attempts) || defined($seconds);

    # Linux-PAM 1.7 retains at most 1024 records and accepts up to seven days.
    die "Login auto-disable requires attempts in 1..1024 and duration in 1..604800 seconds\n"
        unless defined($attempts) && $attempts =~ /^[0-9]+$/ && $attempts >= 1 && $attempts <= 1024
            && defined($seconds) && $seconds =~ /^[0-9]+$/ && $seconds >= 1 && $seconds <= 604800;

    die "Login auto-disable requires Debian's PAM profile manager and the faillock module and utility\n"
        unless -x $pam_update && -x $faillock
            && grep { -r $_ } glob('/usr/lib/*/security/pam_faillock.so /usr/lib/security/pam_faillock.so');

    my @login_paths = ('system login');
    if ($config->exists('routing routing-instance')) {
        push @login_paths, map { "routing routing-instance $_ system login" }
            $config->listNodes('routing routing-instance');
    }
    die "Login auto-disable supports only local PAM password authentication\n"
        if (grep { $_ ne 'local' } @$chain)
            || (grep { $config->exists("$_ radius-server") || $config->exists("$_ tacplus-server") }
                @login_paths);

    die "Login auto-disable requires a managed local-only $common_auth stack\n"
        unless _local_auth_stack(_read_file($common_auth));
    return "conf=/dev/null dir=$tally_dir silent local_users_only deny=$attempts unlock_time=$seconds";
}

sub _update_pam {
    local $ENV{DEBIAN_FRONTEND} = 'noninteractive';
    return system($pam_update, '--package', @_) == 0;
}

sub configure_lockout {
    my ($options) = @_;
    my @names = ($failure, $success, $legacy);
    my $old_stack = _read_file($common_auth);
    my %previous;
    for my $name (@names) {
        my $path = "$profile_dir/$name";
        die "Cannot manage symlink $path\n" if -l $path;
        $previous{$name} = _read_file($path) if -e $path;
    }

    my $owned_rule = qr/pam_tally2?\.so|pam_faillock\.so .*dir=\Q$tally_dir\E(?: |$)/;
    if (!defined($options) && !%previous && !grep { /$owned_rule/ } _auth_rules($old_stack)) {
        die "pam-auth-update failed\n" unless _update_pam();
        return;
    }

    my $ok = eval {
        if (defined($options)) {
            # pam_unix success jumps over both the failure record and pam_deny.
            # Authentication failures terminate before the success reset.
            _write_profile($failure, "Name: Vyatta login failure recording\nDefault: yes\n" .
                "Priority: 0\nAuth-Type: Primary\nAuth:\n" .
                "    [default=die] pam_faillock.so authfail $options\n");
            _write_profile($success, "Name: Vyatta login success reset\nDefault: yes\n" .
                "Priority: 1024\nAuth-Type: Additional\nAuth:\n" .
                "    required pam_faillock.so authsucc $options\n");
            die "pam-auth-update failed enabling login auto-disable\n"
                unless _update_pam('--remove', $legacy, '--enable', $failure, $success);
            die "PAM did not activate the expected login auto-disable stack\n"
                unless _local_auth_stack(_read_file($common_auth), $options);
            _write_profile($legacy, undef);
        } else {
            die "pam-auth-update failed disabling login auto-disable\n"
                unless _update_pam('--remove', @names);
            my @rules = _auth_rules(_read_file($common_auth));
            die "PAM still loads login auto-disable; review $common_auth\n"
                if grep { /$owned_rule/ } @rules;
            _write_profile($_, undef) for @names;
        }
        1;
    };
    return if $ok;

    my $error = $@;
    _write_profile($_, $previous{$_}) for @names;
    if (_read_file($common_auth) ne $old_stack) {
        my @enable;
        push @enable, $failure, $success if $old_stack =~ /pam_faillock\.so .*dir=\Q$tally_dir\E/;
        push @enable, $legacy if $old_stack =~ /pam_tally2?\.so/;
        my %enable = map { $_ => 1 } @enable;
        my @remove = grep { !$enable{$_} } @names;
        my @args = ((@remove ? ('--remove', @remove) : ()), (@enable ? ('--enable', @enable) : ()));
        warn "Could not restore PAM login auto-disable state; review $common_auth\n"
            unless _update_pam(@args) && _read_file($common_auth) eq $old_stack;
    }
    die $error;
}

sub migrate_legacy {
    my $stack = _read_file($common_auth);
    return unless $stack =~ /pam_tally2?\.so/;
    die "Cannot safely migrate a custom legacy login stack; review $common_auth\n"
        unless _local_auth_stack($stack);
    my ($attempts, $seconds) = $stack =~ /^auth\s+required\s+pam_tally\.so\s+onerr=fail\s+deny=([0-9]+)\s+unlock_time=([0-9]+)\s*$/m;
    die "Unsupported legacy login auto-disable parameters\n"
        unless defined($attempts) && $attempts >= 1 && $attempts <= 1024
            && $seconds >= 1 && $seconds <= 604800;
    die "Cannot migrate login auto-disable without faillock\n"
        unless -x $pam_update && -x $faillock
            && grep { -r $_ } glob('/usr/lib/*/security/pam_faillock.so /usr/lib/security/pam_faillock.so');
    configure_lockout("conf=/dev/null dir=$tally_dir silent local_users_only deny=$attempts unlock_time=$seconds");
}

sub _faillock_command {
    return ($faillock, '--conf', '/dev/null', '--dir', $tally_dir, @_);
}

sub reset_tally {
    my ($user) = @_;
    die "Expected an existing user to reset\n"
        unless defined($user) && !ref($user) && $user =~ m{^[^/\s\x00]+$} && defined(getpwnam($user));
    return unless -d $tally_dir;
    system(_faillock_command('--user', $user, '--reset')) == 0
        or die "Could not reset the login failure counter for $user\n";
}

sub tally_counts {
    my %counts;
    return %counts unless -d $tally_dir;
    my @cmd = _faillock_command();
    my @lines;
    local $ENV{LC_ALL} = 'C';
    run3(\@cmd, \undef, \@lines);
    die "Could not read the login failure counters\n" if $? != 0;
    my $user;
    for my $line (@lines) {
        if ($line =~ /^([^\s:]+):$/) {
            $user = $1;
        } elsif (defined($user) && $line =~ /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .* V\s*$/) {
            $counts{$user}++;
        }
    }
    return %counts;
}

1;
