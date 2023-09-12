#!/usr/bin/perl
use utf8;
use Test::More;
use Crypt::OpenSSL::Base::Func ;

#aes_cmac: test vector from RFC 4493
my $key = pack("H*", '2b7e151628aed2a6abf7158809cf4f3c');

my $msg_1 =  pack("H*", '6bc1bee22e409f96e93d7e117393172a');
my $mac_1 = aes_cmac('aes-128-cbc', $key, $msg_1 );
is($mac_1, pack("H*", '070A16B46B4D4144F79BDD9DD04A287C'), 'aes_cmac');


my $msg_2 = pack("H*", '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411');
my $mac_2 = aes_cmac('aes-128-cbc', $key, $msg_2 );
is($mac_2, pack("H*", 'DFA66747DE9AE63030CA32611497C827'), 'aes_cmac');



done_testing();
