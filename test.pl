# $Id: test.pl,v 1.1 2001/04/20 07:09:23 btrott Exp $

my $loaded;
BEGIN { print "1..1\n" }
use Convert::PEM;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }
