# $Id: Makefile.PL,v 1.2 2001/04/20 21:41:51 btrott Exp $

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
        'Crypt::DES' => 0,
    },
);
