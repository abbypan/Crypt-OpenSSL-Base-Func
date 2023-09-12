#!/usr/bin/perl
use strict;
use warnings;
#use lib '../lib';

use Test::More;
use Crypt::OpenSSL::Base::Func;
use FindBin;
use Smart::Comments;
use Data::Dumper;



my $group_name = "prime256v1";
my $nid = OBJ_sn2nid($group_name);
my $group = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name($nid);
# $group
my $ctx   = Crypt::OpenSSL::Bignum::CTX->new();

my $pub_hex = read_ec_pubkey_from_pem("$FindBin::RealBin/ecc_nist_p256_pub.pem");
is($pub_hex, '04259CB35D781B478BF785DE062E1A3577348290BC05E36F3B42B496CF59BF03E965FB768014225FB520B5CBFC2F52240CD80536CAC8716412EA1AF78D4962C0AF', "read_ec_pubkey_from_pem $group_name");

#my $pub_pkey = evp_pkey_from_point_hex($group, $pub_hex, $ctx);
my $pub_pkey = gen_ec_pubkey($group_name, $pub_hex);
my $pub_hex2= read_ec_pubkey($pub_pkey);
is($pub_hex, $pub_hex2, "gen_ec_pubkey $group_name");
write_pubkey_to_pem("$FindBin::RealBin/ecc_nist_p256_pub.recover.pem", $pub_pkey);


my $priv_hex = read_ec_key_from_pem("$FindBin::RealBin/ecc_nist_p256_priv.pem");
is($priv_hex, '732B18540FCB731FD3C46E6D4E19A56525346A8A30D0B7B7B2547283978584E9', "read_ec_key_from_pem $group_name");

my $priv_pkey_gen = gen_ec_key($group_name,  $priv_hex);
#pem_write_evp_pkey("/tmp/test.pem", $priv_pkey_gen, 1);
my $priv_hex_gen = read_ec_key($priv_pkey_gen);
is($priv_hex_gen, $priv_hex, "gen_ec_key $group_name");

my $priv_pkey = gen_ec_key($group_name, $priv_hex);
#pem_write_evp_pkey("/tmp/b.pem", $priv_pkey, 1);

my $priv_hex2= read_ec_key($priv_pkey);
is($priv_hex2, $priv_hex, "read_ec_key $group_name");


$group_name = 'X25519';
$pub_hex = read_ec_pubkey_from_pem("$FindBin::RealBin/x25519_a_pub.pem");
is($pub_hex, '6752249C66966D26DDBF1A75D6ABBACDD04B9D65FFE5171FCDE492A25FFF763E', "read_ec_pubkey_from_pem $group_name");
$pub_pkey = gen_ec_pubkey($group_name, $pub_hex);
$pub_hex2= read_ec_pubkey($pub_pkey);
is($pub_hex, $pub_hex2, "gen_ec_pubkey $group_name");
#$pub_hex = 

$group_name = 'X25519';
#my $nid = OBJ_sn2nid($group_name);
# $nid
#my $group = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name($nid);
## $group
#my $ctx   = Crypt::OpenSSL::Bignum::CTX->new();

$priv_hex = read_ec_key_from_pem("$FindBin::RealBin/x25519_a_priv.pem");
is($priv_hex, 'F8A6DA9856A869DB859C47C0F10021585444BA7A8E00E4FB44564F5851317B50', "read_ec_key_from_pem $group_name");
$priv_pkey_gen = gen_ec_key($group_name,  $priv_hex);
write_key_to_pem("$FindBin::RealBin/x25519_a_priv.recover.pem", $priv_pkey_gen);
$priv_hex_gen = read_ec_key($priv_pkey_gen);
is($priv_hex, $priv_hex_gen, "gen_ec_key $group_name");


#my $priv_pkey = evp_pkey_from_priv_hex($group, $priv_hex);
#pem_write_evp_pkey("/tmp/b.pem", $priv_pkey, 1);

#my $priv_hex2= read_ec_key($priv_pkey);
#is($priv_hex2, $priv_hex, "read_ec_key $group_name");

#}

#my $pkey4=gen_ec_key('X25519', ''); 
#pem_write_evp_pkey("/tmp/d.pem", $pkey4, 1);

#my $pkey3=gen_ec_key('prime256v1', '');
#pem_write_evp_pkey("/tmp/c.pem", $pkey3, 1);
#my $priv_hex3 = read_ec_key($pkey3);
#
#my $priv_hex3= read_ec_key($pkey3);
#print "$priv_hex3\n";

#my $params_raw ;
#my $params_pub;

#print_pkey_gettable_params($pkey3);
#$params_pub = get_pkey_utf8_string_param($pkey3, 'group');
#print $params_pub, "\n";
#$params_raw= get_pkey_bn_param($pkey3, 'p');
#print Dumper($params_raw->to_hex());
#$params_pub = get_pkey_octet_string_param($pkey3, 'priv');
#print $params_pub, "\n";
#
#print "=======================\n";

#print_pkey_gettable_params($pkey4);
#$params_pub = get_pkey_utf8_string_param($pkey4, 'group');
#print $params_pub, "\n";
#$params_raw = get_pkey_bn_param($pkey4, 'pub');
#print Dumper($params_raw->to_hex());
#$params_pub = get_pkey_octet_string_param($pkey4, 'priv');
#print $params_pub, "\n";

#dump_ec_params_raw($params_raw);

done_testing;

1;

