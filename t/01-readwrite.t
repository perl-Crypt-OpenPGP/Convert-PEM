# $Id: 01-readwrite.t,v 1.1 2001/04/22 07:22:42 btrott Exp $

use strict;

use Test;
use Convert::PEM;
use Math::BigInt;

BEGIN { plan tests => 15 };

my $objfile = "./object.pem";

my $pem = Convert::PEM->new(
           Name => 'TEST OBJECT',
           ASN  => qq(
               TestObject SEQUENCE {
                   int INTEGER
               }
    ));
ok($pem);

my($obj, $obj2);
$obj = { TestObject => { int => 4 } };

ok($pem->write( Filename => $objfile, Content => $obj));
ok(-e $objfile);
$obj2 = $pem->read( Filename => $objfile );
ok($obj2);
ok($obj->{TestObject}{int}, $obj2->{TestObject}{int});
unlink $objfile;

ok($pem->write( Filename => $objfile, Content => $obj, Password => 'xx' ));
ok(-e $objfile);
$obj2 = $pem->read( Filename => $objfile );
ok(!$obj2);
ok($pem->errstr =~ /^Decryption failed/);
$obj2 = $pem->read( Filename => $objfile, Password => 'xx');
ok($obj2);
ok($obj->{TestObject}{int}, $obj2->{TestObject}{int});
unlink $objfile;

$obj->{TestObject}{int} = Math::BigInt->new("110982309809809850938509");
ok($pem->write( Filename => $objfile, Content => $obj));
ok(-e $objfile);
$obj2 = $pem->read( Filename => $objfile );
ok($obj2);
ok($obj->{TestObject}{int}, $obj2->{TestObject}{int});
unlink $objfile;
