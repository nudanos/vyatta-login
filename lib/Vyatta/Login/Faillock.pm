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
my $pam_update  = '/usr/sbin/pam-auth-update';
my $faillock    = '/usr/sbin/faillock';
my $tally_dir   = '/run/vyatta-faillock';
my $legacy      = 'vyatta-pam-tally';
my $failure     = 'vyatta-faillock-authfail';
my $success     = 'vyatta-faillock-authsucc';

# Linux-PAM 1.7 retains at most 1024 records and accepts up to seven days.
my $max_attempts = 1024;
my $max_seconds  = 604800;

my $number = qr/[0-9]+/x;
my $space  = qr/[ ]/x;

# A rule of ours in a stack _auth_rules has normalized.
my $owned_rule = qr/pam_tally2?[.]so|pam_faillock[.]so[ ].*dir=\Q$tally_dir\E(?:[ ]|$)/x;

sub _read_file {
    my ($path) = @_;
    open( my $fh, '<', $path ) or die "Cannot read $path: $!\n";
    my $contents = do { local $/ = undef; <$fh> };
    close($fh) or die "Cannot read $path: $!\n";
    return $contents // '';
}

sub _write_profile {
    my ( $name, $contents ) = @_;
    my $path = "$profile_dir/$name";
    if ( !defined($contents) ) {
        if ( -e $path || -l $path ) {
            unlink($path) or die "Cannot remove $path: $!\n";
        }
        return;
    }
    my ( $fh, $tmp ) = tempfile( 'vyatta-XXXXXX', DIR => $profile_dir, SUFFIX => '~', UNLINK => 1 );
    chmod( 0644, $tmp )   or die "Cannot set permissions on $tmp: $!\n";
    print {$fh} $contents or die "Cannot write $tmp: $!\n";
    close($fh)            or die "Cannot close $tmp: $!\n";
    rename( $tmp, $path ) or die "Cannot install $path: $!\n";
    return;
}

sub _auth_rules {
    my ($stack) = @_;
    my @rules;
    for ( split( /\n/x, $stack ) ) {
        s/\s*[#].*$//x;
        s/^\s+|\s+$//gx;
        s/\s+/ /gx;
        push @rules, $_ if length($_);
    }
    return @rules;
}

# The lockout options of both pam_faillock rules.
sub _options {
    my ( $attempts, $seconds ) = @_;
    return
      "conf=/dev/null dir=$tally_dir silent local_users_only deny=$attempts unlock_time=$seconds";
}

# The pam_tally rule the previous package generated, from "required" on, with
# $gap between its words and the given deny and unlock_time values.
sub _legacy_rule {
    my ( $gap, $deny, $unlock ) = @_;
    my $module = qr/required${gap}pam_tally[.]so${gap}onerr=fail/x;
    return qr/${module}${gap}deny=${deny}${gap}unlock_time=${unlock}/x;
}

# The attempts and seconds of a normalized rule that has the generated form.
sub _legacy_values {
    my ($rule) = @_;
    my $form = _legacy_rule( $space, qr/($number)/x, qr/($number)/x );
    return $rule =~ /^auth[ ]${form}$/x;
}

# Whether the previous package's profile is installed with these values.
sub _owns_legacy_profile {
    my ( $attempts, $seconds ) = @_;
    my $path = "$profile_dir/$legacy";
    return 0 if -l $path || !-f $path;
    my $profile = _read_file($path);
    my $rule    = _legacy_rule( $space, qr/\Q$attempts\E/x, qr/\Q$seconds\E/x );
    return $profile =~ /^Name:[ ]Vyatta[ ]pam[ ]tally\s*$/mx
      && $profile   =~ /^\s+${rule}\s*$/mx;
}

# Whether the failure and success rules are the pair this module generates.
sub _lockout_rules_ok {
    my ( $fail, $succeed, $expected_options ) = @_;
    my $recording = qr/auth[ ]\[default=die\][ ]pam_faillock[.]so[ ]authfail/x;
    my ($options) = $fail =~ /^${recording}[ ](.+)$/x;
    return 0 if !defined($options);
    my ( $deny, $unlock ) = $options =~ /[ ]deny=($number)[ ]unlock_time=($number)$/x;
    return 0 if !defined($deny) || $options ne _options( $deny, $unlock );
    return 0 if defined($expected_options) && $options ne $expected_options;
    return $succeed eq "auth required pam_faillock.so authsucc $options";
}

sub _local_auth_stack {
    my ( $stack, $expected_options ) = @_;
    my @rules = _auth_rules($stack);

    # Debian's optional capabilities profile follows the managed stack.
    pop @rules if @rules && $rules[-1] =~ /^auth[ ]optional[ ]pam_cap[.]so(?:[ ]|$)/x;

    # The old generated profile was a Primary rule before pam_unix.
    # Accept only its exact form, and only with the matching owned profile.
    if ( @rules == 4 && ( my @legacy_values = _legacy_values( $rules[0] ) ) ) {
        return 0 if !_owns_legacy_profile(@legacy_values);
        shift @rules;
    }
    my $has_lockout = grep { /pam_faillock[.]so/x } @rules;
    my ( $unix, $deny, $permit ) = @rules;
    my $jump = 1;
    if ($has_lockout) {
        return 0 if @rules != 5;
        ( $unix, my $fail, $deny, $permit, my $succeed ) = @rules;
        return 0 if !_lockout_rules_ok( $fail, $succeed, $expected_options );
        $jump = 2;
    }
    elsif ( @rules != 3 || defined($expected_options) ) {
        return 0;
    }

    my $on_success = qr/\[success=${jump}[ ]default=ignore\]/x;
    return
         $unix =~ /^auth[ ]${on_success}[ ]pam_unix[.]so(?:[ ]|$)/x
      && $deny eq 'auth requisite pam_deny.so'
      && $permit eq 'auth required pam_permit.so';
}

sub _in_range {
    my ( $value, $max ) = @_;
    return defined($value) && $value =~ /^[0-9]+$/x && $value >= 1 && $value <= $max;
}

sub _faillock_available {
    my @modules =
      grep { -r } glob('/usr/lib/*/security/pam_faillock.so /usr/lib/security/pam_faillock.so');
    return -x $pam_update && -x $faillock && @modules > 0;
}

sub validate_lockout {
    my ( $attempts, $seconds, $config, $chain ) = @_;
    return unless defined($attempts) || defined($seconds);

    die "Login auto-disable requires attempts in 1..$max_attempts"
      . " and duration in 1..$max_seconds seconds\n"
      if !_in_range( $attempts, $max_attempts ) || !_in_range( $seconds, $max_seconds );

    die "Login auto-disable requires Debian's PAM profile manager"
      . " and the faillock module and utility\n"
      if !_faillock_available();

    my @login_paths = ('system login');
    if ( $config->exists('routing routing-instance') ) {
        push @login_paths,
          map { "routing routing-instance $_ system login" }
          $config->listNodes('routing routing-instance');
    }
    die "Login auto-disable supports only local PAM password authentication\n"
      if ( grep { $_ ne 'local' } @$chain )
      || ( grep { $config->exists("$_ radius-server") || $config->exists("$_ tacplus-server") }
        @login_paths );

    die "Login auto-disable requires a managed local-only $common_auth stack\n"
      unless _local_auth_stack( _read_file($common_auth) );
    return _options( $attempts, $seconds );
}

sub _update_pam {
    my @args = @_;
    local $ENV{DEBIAN_FRONTEND} = 'noninteractive';
    return system( $pam_update, '--package', @args ) == 0;
}

sub _enable_lockout {
    my ($options) = @_;

    # pam_unix success jumps over both the failure record and pam_deny.
    # Authentication failures terminate before the success reset.
    _write_profile( $failure,
            "Name: Vyatta login failure recording\nDefault: yes\n"
          . "Priority: 0\nAuth-Type: Primary\nAuth:\n"
          . "    [default=die] pam_faillock.so authfail $options\n" );
    _write_profile( $success,
            "Name: Vyatta login success reset\nDefault: yes\n"
          . "Priority: 1024\nAuth-Type: Additional\nAuth:\n"
          . "    required pam_faillock.so authsucc $options\n" );
    die "pam-auth-update failed enabling login auto-disable\n"
      unless _update_pam( '--remove', $legacy, '--enable', $failure, $success );
    die "PAM did not activate the expected login auto-disable stack\n"
      unless _local_auth_stack( _read_file($common_auth), $options );
    _write_profile( $legacy, undef );
    return;
}

sub _disable_lockout {
    my @names = @_;
    die "pam-auth-update failed disabling login auto-disable\n"
      unless _update_pam( '--remove', @names );
    my @rules = _auth_rules( _read_file($common_auth) );
    die "PAM still loads login auto-disable; review $common_auth\n"
      if grep { $_ =~ $owned_rule } @rules;
    _write_profile( $_, undef ) for @names;
    return;
}

# After a failed change: the profiles as they were, and the stack too if
# pam-auth-update had already rewritten it.
sub _restore_lockout {
    my ( $old_stack, $previous, @names ) = @_;
    _write_profile( $_, $previous->{$_} ) for @names;
    return if _read_file($common_auth) eq $old_stack;
    my @enable;
    push @enable, $failure, $success
      if $old_stack =~ /pam_faillock[.]so[ ].*dir=\Q$tally_dir\E/x;
    push @enable, $legacy if $old_stack =~ /pam_tally2?[.]so/x;
    my %enable = map  { $_ => 1 } @enable;
    my @remove = grep { !$enable{$_} } @names;
    my @args =
      ( ( @remove ? ( '--remove', @remove ) : () ), ( @enable ? ( '--enable', @enable ) : () ) );
    warn "Could not restore PAM login auto-disable state; review $common_auth\n"
      unless _update_pam(@args) && _read_file($common_auth) eq $old_stack;
    return;
}

sub configure_lockout {
    my ($options) = @_;
    my @names     = ( $failure, $success, $legacy );
    my $old_stack = _read_file($common_auth);
    my %previous;
    for my $name (@names) {
        my $path = "$profile_dir/$name";
        die "Cannot manage symlink $path\n"  if -l $path;
        $previous{$name} = _read_file($path) if -e $path;
    }

    if ( !defined($options) && !%previous && !grep { $_ =~ $owned_rule } _auth_rules($old_stack) ) {
        die "pam-auth-update failed\n" unless _update_pam();
        return;
    }

    my $ok = eval {
        if ( defined($options) ) {
            _enable_lockout($options);
        }
        else {
            _disable_lockout(@names);
        }
        1;
    };
    return if $ok;

    my $error = $@;
    _restore_lockout( $old_stack, \%previous, @names );
    chomp $error;
    die "$error\n";
}

sub migrate_legacy {
    my $stack = _read_file($common_auth);
    return unless $stack =~ /pam_tally2?[.]so/x;
    die "Cannot safely migrate a custom legacy login stack; review $common_auth\n"
      unless _local_auth_stack($stack);
    my $rule = _legacy_rule( qr/\s+/x, qr/($number)/x, qr/($number)/x );
    my ( $attempts, $seconds ) = $stack =~ /^auth\s+${rule}\s*$/mx;
    die "Unsupported legacy login auto-disable parameters\n"
      if !_in_range( $attempts, $max_attempts ) || !_in_range( $seconds, $max_seconds );
    die "Cannot migrate login auto-disable without faillock\n" if !_faillock_available();
    configure_lockout( _options( $attempts, $seconds ) );
    return;
}

sub _faillock_command {
    my @args = @_;
    return ( $faillock, '--conf', '/dev/null', '--dir', $tally_dir, @args );
}

sub reset_tally {
    my ($user) = @_;
    my $is_name = defined($user) && !ref($user) && $user =~ m{^[^/\s\x00]+$}x;
    die "Expected an existing user to reset\n" if !$is_name || !defined( getpwnam($user) );
    return unless -d $tally_dir;
    system( _faillock_command( '--user', $user, '--reset' ) ) == 0
      or die "Could not reset the login failure counter for $user\n";
    return;
}

sub tally_counts {
    my %counts;
    return %counts unless -d $tally_dir;
    my @cmd = _faillock_command();
    my @lines;
    local $ENV{LC_ALL} = 'C';
    run3( \@cmd, \undef, \@lines );
    die "Could not read the login failure counters\n" if $? != 0;
    my $user;

    for my $line (@lines) {
        if ( $line =~ /^([^\s:]+):$/x ) {
            $user = $1;
        }
        elsif ( defined($user) && $line =~ /^\d{4}-\d{2}-\d{2}[ ]\d{2}:\d{2}:\d{2}[ ].*[ ]V\s*$/x )
        {
            $counts{$user}++;
        }
    }
    return %counts;
}

1;
