package Vyatta::Config;
use strict;
use warnings;
sub new          { my ($class) = @_; return bless {}, $class }
sub returnValues { return $ENV{TEST_REMOTE} ? ( "radius", "local" ) : (); }

sub returnValue {
    my ( $self, $path ) = @_;
    return unless $ENV{TEST_ENABLE_LOCKOUT};
    return $ENV{TEST_DENY}   // 2  if $path eq "system login auto-disable attempts";
    return $ENV{TEST_UNLOCK} // 30 if $path eq "system login auto-disable duration";
    return;
}
sub isChanged { return 0; }

## no critic (Subroutines::ProhibitBuiltinHomonyms) reason: as the real module
sub exists { return 0; }
1;
