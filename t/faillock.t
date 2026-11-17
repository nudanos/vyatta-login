#!/usr/bin/perl
# Login auto-disable rewrites /etc/pam.d/common-auth through pam-auth-update,
# and only when the stack there is exactly the one it manages: local password
# authentication, with or without its own pam_faillock rules. Anything else
# (another module, another faillock directory, a different jump count) must
# be refused, or enabling lockout could leave a stack that lets a failed
# login through. These are the recognition rules and the input checks.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Vyatta::Login::Faillock qw(validate_lockout reset_tally);

my $opts  = 'conf=/dev/null dir=/run/vyatta-faillock silent local_users_only deny=3 unlock_time=60';
my $plain = <<'END';
# here are the per-package modules (the "Primary" block)
auth	[success=1 default=ignore]	pam_unix.so nullok
# here's the fallback if no module succeeds
auth	requisite			pam_deny.so
auth	required			pam_permit.so   # prime the stack
END
my $locked = <<"END";
auth	[success=2 default=ignore]	pam_unix.so nullok
auth	[default=die]	pam_faillock.so authfail $opts
auth	requisite			pam_deny.so
auth	required			pam_permit.so
auth	required	pam_faillock.so authsucc $opts
END

sub stack_ok { return Vyatta::Login::Faillock::_local_auth_stack(@_) }

is_deeply(
    [ Vyatta::Login::Faillock::_auth_rules($plain) ],
    [
        'auth [success=1 default=ignore] pam_unix.so nullok',
        'auth requisite pam_deny.so',
        'auth required pam_permit.so',
    ],
    'rules: comments and blank lines dropped, whitespace collapsed'
);

ok( stack_ok($plain),                                         'local-only stack without lockout' );
ok( stack_ok( $plain . "auth\toptional\t\t\tpam_cap.so \n" ), '... followed by pam_cap' );
ok( !stack_ok( $plain, $opts ),                         '... is not a stack with lockout enabled' );
ok( stack_ok($locked),                                  'local-only stack with lockout' );
ok( stack_ok( $locked . "auth optional pam_cap.so\n" ), '... followed by pam_cap' );
ok( stack_ok( $locked, $opts ),                         '... with the expected options' );
ok( !stack_ok( $locked, $opts =~ s/deny=3/deny=4/r ),   '... but not with other options' );

sub changed {
    my ( $stack, $from, $to ) = @_;
    $stack =~ s/\Q$from\E/$to/ or die "no '$from'";
    return $stack;
}
ok(
    !stack_ok( changed( $locked, 'success=2', 'success=1' ) ),
    'refused: pam_unix success would land on pam_deny'
);
ok(
    !stack_ok( changed( $plain, 'success=1', 'success=2' ) ),
    'refused: pam_unix success would jump past pam_permit'
);
ok(
    !stack_ok( changed( $locked, "authsucc $opts", 'authsucc' ) ),
    'refused: success reset with other options than failure recording'
);
ok( !stack_ok( changed( $locked, 'dir=/run/vyatta-faillock', 'dir=/var/run/faillock' ) ),
    'refused: another tally directory' );
ok( !stack_ok( changed( $locked, 'local_users_only ', '' ) ), 'refused: an option missing' );
ok(
    !stack_ok( changed( $locked, '[default=die]', 'required' ) ),
    'refused: failure recording that does not end the stack'
);
ok(
    !stack_ok( $plain . "auth sufficient pam_sss.so\n" ),
    'refused: another module after the stack'
);
ok( !stack_ok( "auth sufficient pam_radius_auth.so\n" . $plain ),
    'refused: another module before the stack' );
ok( !stack_ok( changed( $plain, 'requisite', 'optional' ) ),
    'refused: pam_deny that does not deny' );
ok( !stack_ok(''), 'refused: an empty stack' );
ok(
    !stack_ok( "auth required pam_tally.so onerr=fail deny=3 unlock_time=60\n" . $plain ),
    'refused: a legacy pam_tally stack without the profile that owns it'
);

is( scalar( () = validate_lockout( undef, undef ) ),
    0, 'validate: nothing configured, nothing to do' );
for my $bad (
    [ 0,     60 ],
    [ 1025,  60 ],
    [ 3,     0 ],
    [ 3,     604801 ],
    [ '3x',  60 ],
    [ 3,     '1m' ],
    [ 3,     undef ],
    [ undef, 60 ],
    [ -1,    60 ]
  )
{
    my @show = map { $_ // 'undef' } @$bad;
    eval { validate_lockout(@$bad) };
    like(
        $@,
        qr/attempts in 1\.\.1024 and duration in 1\.\.604800 seconds/,
        "validate: refuses attempts=$show[0] duration=$show[1]"
    );
}

for my $bad ( undef, '', 'a/b', "a b", [], 'no-such-user-nudanos-test' ) {
    eval { reset_tally($bad) };
    like(
        $@,
        qr/Expected an existing user to reset/,
        'reset: refuses ' . ( defined $bad ? "'$bad'" : 'undef' )
    );
}

done_testing();
