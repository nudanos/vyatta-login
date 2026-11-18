# Test-only dependencies for executing the complete operational provider.
package LoginProviderFixture;
use strict;
use warnings;

BEGIN {
    $INC{'Vyatta/Configd.pm'} = 1;
    $INC{'Vyatta/Login/Faillock.pm'} = 1;
    $INC{'IPC/Run3.pm'} = 1;
    my $read = 0;
    *CORE::GLOBAL::setpwent = sub { $read = 0 };
    *CORE::GLOBAL::endpwent = sub { };
    *CORE::GLOBAL::getpwent = sub {
        return if $read++;
        return ('alice', '$6$fixture', 1001);
    };
}

package Vyatta::Configd::Client;
sub new { return bless {}, shift }
sub tree_get_full_hash { return { user => [{ tagnode => 'alice' }] } }

package Vyatta::Login::Faillock;
use Exporter 'import';
our @EXPORT_OK = qw(tally_counts);
sub tally_counts {
    die "Could not read the login failure counters\n"
        if $ENV{LOGIN_PROVIDER_CASE} eq 'tally_failure';
    return (alice => 1);
}

package IPC::Run3;
use Exporter 'import';
our @EXPORT = qw(run3);
sub run3 {
    my ($command, undef, $output, $error) = @_;
    if ($command->[0] eq 'chage') {
        @$output = ("Password expires : never\n");
        $? = 0;
        return 1;
    }
    die "Unexpected command @$command\n" unless $command->[0] eq '/usr/bin/last';
    my $case = $ENV{LOGIN_PROVIDER_CASE};
    die "exec /usr/bin/last: No such file or directory\n" if $case eq 'missing';
    @$output = $case eq 'empty' ? () : (
        "alice-other pts/1 2026-10-01T01:02:03+00:00 - gone\n",
        "alice pts/0 2026-11-09T12:34:56-07:00 still logged in\n",
    );
    my $message = $case =~ /^(failed|signal)$/
        ? "BusyBox last: unrecognized option '--time-format'\nUsage: last [-f FILE]\n"
        : $case eq 'warning' ? "last: history warning\n" : '';
    if (ref($error)) {
        $$error = $message;
    } else {
        print STDERR $message;
    }
    $? = $case eq 'failed' ? 256 : $case eq 'signal' ? 9 : 0;
    return 1;
}

1;
