# $Id: Makefile.PL,v 1.3 2001/09/15 03:50:42 btrott Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => 'Convert::PEM',
    DISTNAME => 'Convert-PEM',
    VERSION_FROM => 'lib/Convert/PEM.pm',
    AUTHOR => 'Benjamin Trott <ben@rhumba.pair.com>',
    ABSTRACT => 'Read/write encrypted ASN.1 PEM files',
    PREREQ_PM => {
        'MIME::Base64' => 0,
        'Convert::ASN1' => '0.10',
        'Digest::MD5' => 0,
        'Crypt::DES_EDE3' => 0,
    },
);
