#!/usr/bin/perl
# usermod and useradd call sss_cache, which prints warnings on stderr when
# SSSD is not configured although the change succeeded. _update_user must
# judge by the exit status: treating stderr as failure made every boot
# configuration with a login user fail to commit.
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../lib";
use Vyatta::Login::User;

my $exit = 0;
my @ran;
no warnings 'redefine';
*Vyatta::Login::User::run3 = sub {
    my ( $cmd, undef, undef, $err ) = @_;
    push @ran, $cmd->[0];
    $$err = "[sss_cache] [sss_tool_confdb_init] (0x0010): Can't access '/var/lib/sss/db/config.ldb'\n"
      if ref $err;
    $? = $exit << 8;
    return 1;
};

my $tree = { level => 'admin', authentication => { 'encrypted-password' => '$6$x' } };
eval { Vyatta::Login::User::_update_user( 'root', $tree ) };
is( $@, '', 'warnings on stderr with exit status 0 are not a failure' );
ok( scalar(@ran), 'the account command ran' );

$exit = 1;
eval { Vyatta::Login::User::_update_user( 'root', $tree ) };
like( $@, qr/Attempt to change user root failed/, 'a non-zero exit status is a failure' );

done_testing();
