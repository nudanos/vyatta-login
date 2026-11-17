#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin;
use IPC::Open3;
use JSON qw(decode_json);
use Symbol qw(gensym);

sub provider {
    my ($case) = @_;
    local $ENV{LOGIN_PROVIDER_CASE} = $case;
    my $error = gensym;
    my $pid = open3(undef, my $output, $error, $^X,
        "-I$FindBin::Bin/lib", '-MLoginProviderFixture',
        "$FindBin::Bin/../scripts/system-login-information", '--action=get-state');
    local $/;
    my $stdout = <$output> // '';
    my $stderr = <$error> // '';
    waitpid($pid, 0);
    return ($?, $stdout, $stderr);
}

for my $case (qw(iso warning empty failed signal missing)) {
    subtest $case => sub {
        my ($status, $stdout, $stderr) = provider($case);
        is($status, 0, 'history availability does not fail the provider');
        is($stderr, '', 'handled history diagnostics cannot pollute JSON');
        my $state = eval { decode_json($stdout) };
        ok($state, 'stdout contains valid state JSON') or diag($stdout);
        return unless $state;
        my $user = $state->{user}[0];
        is($user->{name}, 'alice', 'exact account selected');
        is($user->{'tally-counter'}, 1, 'failure counter survives missing history');
        my $expected = $case =~ /^(iso|warning)$/
            ? '2026-11-09T12:34:56-07:00' : 'never logged in';
        is($user->{'last-login'}, $expected, 'valid ISO date or supported fallback');
    };
}

my ($status, $stdout, $stderr) = provider('tally_failure');
isnt($status, 0, 'tally errors remain fatal');
like($stderr, qr/Could not read the login failure counters/, 'tally diagnostic preserved');
is($stdout, '', 'tally failure does not emit success JSON');
done_testing();
