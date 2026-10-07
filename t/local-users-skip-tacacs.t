#!/usr/bin/perl
# update() deletes every local account (uid 1000-29999, in a vyatta group)
# that the configuration does not list. The TACACS+ mapped accounts
# tacacs0..15 (primary group tacacs) are such accounts once vyatta-tacacs
# gives them their level's groups, and deleting them broke TACACS+ login.
use strict;
use warnings;
use Test::More;
use FindBin;

my @pw;
BEGIN {
    no warnings 'once';
    *CORE::GLOBAL::setpwent = sub { };
    *CORE::GLOBAL::endpwent = sub { };
    *CORE::GLOBAL::getpwent = sub { my $e = shift @pw; return $e ? @$e : () };
    *CORE::GLOBAL::getgrnam = sub {
        return unless $_[0] eq 'tacacs';
        return wantarray ? ( 'tacacs', 'x', 990, '' ) : 990;
    };
}
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../lib";
use Vyatta::Login::User;

no warnings 'redefine';
*Vyatta::Login::User::_in_vyatta_group = sub { 1 };

sub entry { my ( $name, $uid, $gid ) = @_; [ $name, 'x', $uid, $gid, '', '', '', "/home/$name", '/bin/vbash' ] }

@pw = ( entry( 'alice', 1001, 100 ), entry( 'tacacs15', 1015, 990 ), entry( 'daemon', 1, 1 ) );
is_deeply( [ Vyatta::Login::User::_local_users() ], ['alice'],
    'TACACS+ mapped accounts are not configurable local users' );

done_testing();
