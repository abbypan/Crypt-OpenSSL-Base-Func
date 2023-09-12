#!/usr/bin/perl
use utf8;
use strict;
use Test::More;
use Crypt::OpenSSL::Base::Func ;
use FindBin;

my $z = ecdh_pem("$FindBin::Bin/x25519_a_priv.pem", "$FindBin::Bin/x25519_b_pub.pem");
is($z, pack("H*", '0D661C303EA035BE2936174FEC0954213D0D7C760F67B9B661414064304A8347'), 'ecdh_pem');

my $z2 = ecdh_pem("$FindBin::Bin/x25519_b_priv.pem", "$FindBin::Bin/x25519_a_pub.pem");
is($z, $z2, 'ecdh_pem');

done_testing();
