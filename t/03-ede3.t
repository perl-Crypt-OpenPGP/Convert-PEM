# $Id: 03-ede3.t,v 1.1 2001/04/22 07:31:08 btrott Exp $

use strict;

use Test;
use Convert::PEM::CBC;

BEGIN { plan tests => 6 };

my $KEY = pack "H64", ("0123456789ABCDEF" x 4);
my $IV  = "\0" x 8;

my($cbc1, $cbc2);

$cbc1 = Convert::PEM::CBC->new(
                  Cipher => 'Crypt::DES_EDE3',
                  Key    => $KEY,
                  IV     => $IV,
         );
ok($cbc1);

$cbc2 = Convert::PEM::CBC->new(
                  Cipher => 'Crypt::DES_EDE3',
                  Key    => $KEY,
                  IV     => $IV,
         );
ok($cbc2);

my($enc, $dec);
$enc = $cbc1->encrypt( _checkbytes() );
ok($enc);
$dec = $cbc2->decrypt($enc);
ok($dec);

ok( vec($dec, 0, 8) == vec($dec, 2, 8) );
ok( vec($dec, 1, 8) == vec($dec, 3, 8) );

sub _checkbytes {
    my($check1, $check2) = (chr int rand 255, chr int rand 255);
    "$check1$check2$check1$check2";
}
