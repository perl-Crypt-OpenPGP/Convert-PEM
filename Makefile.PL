# $Id: Makefile.PL 1829 2005-05-25 21:51:40Z btrott $

use inc::Module::Install;

name('Convert-PEM');
abstract('Read/write encrypted ASN.1 PEM files');
author('Benjamin Trott <ben+cpan@stupidfool.org>');
version_from('lib/Convert/PEM.pm');
license('perl');
no_index(directory => 't');
sign(1);

include('ExtUtils::AutoInstall');

requires('Class::ErrorHandler');
requires('MIME::Base64');
requires('Convert::ASN1' => '0.10');
requires('Digest::MD5');
requires('Crypt::DES_EDE3');

auto_include();
auto_install();

&WriteAll;
