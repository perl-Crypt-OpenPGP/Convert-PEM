# $Id: 00-compile.t,v 1.1 2001/04/22 07:22:42 btrott Exp $

my $loaded;
BEGIN { print "1..1\n" }
use Convert::PEM;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }
