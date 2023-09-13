package Crypt::OpenSSL::Base::Func;

use strict;
use warnings;

use Carp;

require Exporter;
use AutoLoader;
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;
use POSIX;
#use Smart::Comments;

our $VERSION = '0.037';

our @ISA = qw(Exporter);

our @EXPORT = qw( 
export_pubkey
hex2point
bn_mod_sqrt 
aes_cmac 
pkcs12_key_gen 
pkcs5_pbkdf2_hmac
digest
ecdh 
ecdh_pem
gen_ec_key
gen_ec_pubkey
write_key_to_pem
write_pubkey_to_pem
read_ec_key
read_ec_key_from_pem
read_ec_pubkey
read_ec_pubkey_from_pem
read_priv_pkey_from_pem
read_pub_pkey_from_pem
aead_encrypt
aead_decrypt
print_pkey_gettable_params
get_pkey_bn_param
get_pkey_octet_string_param
get_pkey_utf8_string_param

evp_pkey_from_point_hex
evp_pkey_from_priv_hex

sn_point2hex
sn_hex2point
aead_encrypt_split
random_bn
i2osp
generate_ec_key
get_ec_params

OBJ_sn2nid
EVP_PKEY_get1_EC_KEY
EVP_MD_get_block_size
EVP_MD_get_size
EVP_get_digestbyname
EC_GROUP_get_curve
EC_POINT_set_affine_coordinates
EC_POINT_get_affine_coordinates
); 


our @EXPORT_OK = @EXPORT;

require XSLoader;
XSLoader::load( 'Crypt::OpenSSL::Base::Func', $VERSION );

sub sn_hex2point {
    my ($group_name, $point_hex) = @_;

    my $ec_params_r = get_ec_params($group_name);
    #my $point_bn = Crypt::OpenSSL::Bignum->new_from_hex($point_hex);
    my $P = hex2point($ec_params_r->{group}, $point_hex);

    return $P;
}

sub sn_point2hex {
    my ($group_name, $point, $point_compress_t) = @_;
    $point_compress_t //= 4;

    my $ec_params_r = get_ec_params($group_name);
    my $point_hex = Crypt::OpenSSL::EC::EC_POINT::point2hex($ec_params_r->{group}, $point, $point_compress_t, $ec_params_r->{ctx});
    return $point_hex;
}


sub aead_encrypt_split {
    my ($res, $tag_len) = @_;
    my $ciphertext = substr $res, 0, length($res) - $tag_len;
    my $tag = substr $res, length($res) - $tag_len, $tag_len;
    return ($ciphertext, $tag);
}

sub random_bn {
    my ($Nn) = @_; 
    my $range_hex = join("", ('ff') x $Nn);
    my $range = Crypt::OpenSSL::Bignum->new_from_hex($range_hex);

    my $random_bn = Crypt::OpenSSL::Bignum->rand_range($range);
    return $random_bn;
}

sub i2osp {
    my ($len, $L) = @_;  

    my $s = pack "C*", $len;
    $s = unpack("H*", $s);

    my $s_len = length($s);
    my $tmp_l = $L*2;
    if($tmp_l > $s_len){
        my $pad_len = $tmp_l - $s_len;
        substr $s, 0, 0, ('0') x $pad_len;
    }   

    $s = pack("H*", $s);

    return $s; 
}

sub generate_ec_key {
    my ( $group_name, $priv_hex ) = @_;

    my $group;
    if(! ref($group_name)){
        my $nid   = OBJ_sn2nid( $group_name );
        $group = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name( $nid );
    }else{
        $group = $group_name;
    }

    my $ctx   = Crypt::OpenSSL::Bignum::CTX->new();

    my $priv_key = Crypt::OpenSSL::EC::EC_KEY::new();
    $priv_key->set_group( $group );

    my $priv_bn ; 

    if(! $priv_hex){
        $priv_key->generate_key();
        $priv_bn = $priv_key->get0_private_key();
    }else{
     $priv_bn = Crypt::OpenSSL::Bignum->new_from_hex($priv_hex);
    }
    my $priv_pkey = evp_pkey_from_priv_hex( $group, $priv_bn->to_hex );

    #my $pub_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
    #my $zero = Crypt::OpenSSL::Bignum->zero;
    #Crypt::OpenSSL::EC::EC_POINT::mul( $group, $pub_point, $zero, $G, $priv_pkey, $ctx );

    my $ec_key = EVP_PKEY_get1_EC_KEY($priv_pkey);

    my $pub_point      = $ec_key->get0_public_key();
    my $pub_hex  = Crypt::OpenSSL::EC::EC_POINT::point2hex( $group, $pub_point, 4, $ctx );
    my $pub_bin  = pack( "H*", $pub_hex );
    my $pub_pkey = evp_pkey_from_point_hex( $group, $pub_hex, $ctx );

    #EVP_PKEY_new_raw_public_key(int type, ENGINE *e, const unsigned char *key, size_t keylen);

    return {
        priv_pkey => $priv_pkey, priv_key => $priv_key, priv_bn => $priv_bn,
        pub_pkey => $pub_pkey, pub_point => $pub_point, pub_hex => $pub_hex, pub_bin => $pub_bin,
    };

    #my $priv_pkey = gen_ec_key($group_name, $priv_hex);
    #$priv_hex = read_ec_key($priv_pkey);
    #my $priv_bn = Crypt::OpenSSL::Bignum->new_from_hex($priv_hex);
    
        
    #my $pub_pkey = read_ec_pubkey($priv_pkey);
    #my $pub_hex2 = export_pubkey($priv_pkey);
    ### $pub_hex2
    #if(!$pub_hex){
        #print "fail export pubkey\n";
    #}else{
        #print $pub_hex, "\n";
    #}
    #my $pub_pkey = gen_ec_pubkey($group_name, $pub_hex);
    #my $pub_bin = pack("H*", $pub_hex);

    #my $nid   = OBJ_sn2nid( $group_name );
    #my $group = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name( $nid );
    #my $ctx   = Crypt::OpenSSL::Bignum::CTX->new();


    #my $ec_key = EVP_PKEY_get1_EC_KEY($priv_pkey);
    #### $ec_key
    #my $pub_point      = $ec_key->get0_public_key();
    #### $pub_point
    #my $pub_hex  = sn_point2hex($group_name, $pub_point);
    #### $pub_hex
    #my $pub_bin  = pack( "H*", $pub_hex );
    #### $pub_bin
    #my $pub_pkey = gen_ec_pubkey( $group_name, $pub_hex );

    #### $pub_pkey

    #return {
        #priv_pkey => $priv_pkey, priv_hex => $priv_hex, priv_bn => $priv_bn, 
        #pub_pkey => $pub_pkey, pub_hex => $pub_hex, pub_bin => $pub_bin, pub_point => $pub_point,
    #};
} ## end sub generate_ec_key

sub get_ec_params {
    my ( $group_name ) = @_;

    my $nid   = OBJ_sn2nid( $group_name );
    my $group = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name( $nid );
    my $ctx   = Crypt::OpenSSL::Bignum::CTX->new();


    my $p = Crypt::OpenSSL::Bignum->new();
    my $a = Crypt::OpenSSL::Bignum->new();
    my $b = Crypt::OpenSSL::Bignum->new();
    EC_GROUP_get_curve( $group, $p, $a, $b, $ctx );

    my $degree = Crypt::OpenSSL::EC::EC_GROUP::get_degree($group);

    my $order = Crypt::OpenSSL::Bignum->new();
    Crypt::OpenSSL::EC::EC_GROUP::get_order($group, $order, $ctx);

    my $cofactor = Crypt::OpenSSL::Bignum->new();
    Crypt::OpenSSL::EC::EC_GROUP::get_cofactor($group, $cofactor, $ctx);

    return {
        nid => $nid,
        name => $group_name,
        group =>$group,
        p => $p, a=> $a, b=>$b, degree => $degree, order=> $order, cofactor=>$cofactor,
        ctx=> $ctx,
    };
}

1;
__END__

