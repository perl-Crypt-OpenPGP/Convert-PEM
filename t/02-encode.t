# $Id: 02-encode.t,v 1.1 2001/04/22 07:22:42 btrott Exp $

use strict;

use Test;
use Convert::PEM;
use Math::BigInt;

BEGIN { plan tests => 12 };

my $pem = Convert::PEM->new(
           Name => 'TEST OBJECT',
           ASN  => qq(
               TestObject SEQUENCE {
                   int INTEGER
               }
    ));
ok($pem);

my($obj, $obj2, $blob);
$obj = { TestObject => { int => 4 } };

$blob = $pem->encode( Content => $obj);
ok($blob);
$obj2 = $pem->decode( Source => $blob );
ok($obj2);
ok($obj->{TestObject}{int}, $obj2->{TestObject}{int});

$blob = $pem->encode( Content => $obj, Password => 'xx' );
ok($blob);
$obj2 = $pem->decode( Source => $blob );
ok(!$obj2);
ok($pem->errstr =~ /^Decryption failed/);
$obj2 = $pem->decode( Source => $blob, Password => 'xx');
ok($obj2);
ok($obj->{TestObject}{int}, $obj2->{TestObject}{int});

$obj->{TestObject}{int} = Math::BigInt->new("110982309809809850938509");
$blob = $pem->encode( Content => $obj );
ok($blob);
$obj2 = $pem->decode( Source => $blob );
ok($obj2);
ok($obj->{TestObject}{int}, $obj2->{TestObject}{int});
