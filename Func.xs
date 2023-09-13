#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


unsigned char * bin2hex(const unsigned char * bin, size_t bin_len)
{

	unsigned char   *out = NULL;
	size_t  out_len;
    size_t n = bin_len*2 + 1;
    
    out = OPENSSL_malloc(n);
    OPENSSL_buf2hexstr_ex(out, n, &out_len, bin, bin_len, '\0');

    return out;

    /*if (bin == NULL || bin_len == 0)*/
        /*return NULL;*/

    /*out = malloc(n);*/
    /*int i;*/
    /*for (i=0; i<bin_len; i++) {*/
        /*out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];*/
        /*out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];*/
    /*}*/
    /*out[bin_len*2] = '\0';*/

    /*return out;*/
}

unsigned char* read_ec_key(EVP_PKEY *pkey)
{
    BIGNUM *priv_bn = NULL;
    char* priv_hex = NULL;
    char* priv = NULL;
    size_t priv_len=0;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn);

    if(priv_bn==NULL){

        EVP_PKEY_get_raw_private_key(pkey, NULL, &priv_len);
        priv = OPENSSL_malloc(priv_len);
        EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len);

        priv_bn = BN_bin2bn(priv, priv_len, NULL);
        OPENSSL_free(priv);
    }

    priv_hex = BN_bn2hex(priv_bn);

    OPENSSL_free(priv_bn);

    return priv_hex;
}

unsigned char* read_ec_key_from_pem(unsigned char* keyfile) 
{

    FILE *inf = NULL; 
    EVP_PKEY *pkey = NULL;
    unsigned char* priv_hex = NULL;

    inf = fopen(keyfile, "r");
    pkey = PEM_read_PrivateKey(inf, NULL, NULL, NULL);

    priv_hex = read_ec_key(pkey);

    OPENSSL_free(pkey);

    return priv_hex;

}

unsigned char* export_pubkey(EVP_PKEY *priv_pkey)
{
    unsigned char *pubkey = NULL;
    size_t pubkey_len;
    unsigned char *pub_hex = NULL;

    pubkey_len = EVP_PKEY_get1_encoded_public_key(priv_pkey, &pubkey);
    pub_hex = bin2hex(pubkey, pubkey_len);

    if(pubkey) OPENSSL_free(pubkey);

    return pub_hex;
}


unsigned char* read_ec_pubkey(EVP_PKEY *pkey)
{

    unsigned char* pub=NULL;
    size_t pub_len;
    char* pub_hex = NULL;

    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL,  0, &pub_len);
    pub = OPENSSL_malloc(pub_len);
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, pub_len, NULL);

    /*EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);*/

    pub_hex = bin2hex(pub, pub_len);

    OPENSSL_free(pub);
    
    return pub_hex;
}

EVP_PKEY* evp_pkey_from_point_hex(EC_GROUP* group, char* point_hex, BN_CTX* ctx)  
{
    EC_KEY* ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, group);

    EC_POINT* ec_pub_point = EC_POINT_new(group);
    ec_pub_point = EC_POINT_hex2point(group, point_hex, ec_pub_point, ctx);
    EC_KEY_set_public_key(ec_key, ec_pub_point);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    return pkey;
}

EVP_PKEY* evp_pkey_from_priv_hex(EC_GROUP* group, char* priv_hex)  
{
    EC_KEY* ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, group);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

    BIGNUM *priv_bn = BN_new();
    BN_hex2bn(&priv_bn, priv_hex);
    EC_KEY_set_private_key(ec_key, (const BIGNUM *) priv_bn);

    EC_POINT* ec_pub_point = EC_POINT_new(group);
    EC_POINT_mul(group, ec_pub_point, priv_bn, NULL, NULL, NULL);
    EC_KEY_set_public_key(ec_key, ec_pub_point);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    return pkey;

}


unsigned char* read_ec_pubkey_from_pem(char* keyfile) 
{

    FILE *inf; 
    EVP_PKEY *pkey = NULL;
    unsigned char * pub_hex =NULL;

    inf = fopen(keyfile, "r");
    pkey = PEM_read_PUBKEY(inf, NULL, NULL, NULL);

    pub_hex = read_ec_pubkey(pkey);

    OPENSSL_free(pkey);

    return pub_hex;
}

EVP_PKEY* read_priv_pkey_from_pem(unsigned char *keyfile)
{
    FILE *inf = fopen(keyfile, "r");

    EVP_PKEY *pkey = NULL;

    pkey = PEM_read_PrivateKey(inf, NULL, NULL, NULL);

    return pkey;

}

EVP_PKEY* read_pub_pkey_from_pem(unsigned char *keyfile)
{
    FILE *inf = fopen(keyfile, "r");

    EVP_PKEY *pkey = NULL;

    pkey = PEM_read_PUBKEY(inf, NULL, NULL, NULL);

    return pkey;

}


unsigned char* bn_mod_sqrt(unsigned char *a, unsigned char *p)
{
unsigned char *s=NULL;

    BN_CTX *ctx;
    BIGNUM *bn_a, *bn_p, *bn_s, *ret;

    ctx = BN_CTX_new();

    bn_a = BN_new();
    BN_hex2bn(&bn_a, a); 

    bn_p = BN_new();
    BN_hex2bn(&bn_p, p);

    bn_s = BN_new();
    ret = BN_mod_sqrt(bn_s, bn_a, bn_p, ctx);

    if(ret != NULL){
        s = BN_bn2hex(bn_s);
    }

    BN_free(bn_a);
    BN_free(bn_p);
    BN_free(bn_s);
    BN_CTX_free(ctx);

    return s;
}

unsigned char* aes_cmac_raw(unsigned char* cipher_name, unsigned char* key, size_t key_len, unsigned char* msg, size_t msg_len, size_t *out_len_ptr ) 
{
// https://github.com/openssl/openssl/blob/master/demos/mac/cmac-aes256.c

    unsigned char* out=NULL;

    OSSL_LIB_CTX *library_context = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[4], *p = params;

    library_context = OSSL_LIB_CTX_new();
    mac = EVP_MAC_fetch(library_context, "CMAC", NULL);
    mctx = EVP_MAC_CTX_new(mac);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, sizeof(cipher_name));
    *p = OSSL_PARAM_construct_end();


    EVP_MAC_init(mctx, key, key_len, params);
    EVP_MAC_update(mctx, msg, msg_len);

    EVP_MAC_final(mctx, NULL, out_len_ptr, 0);
    out = OPENSSL_malloc(*out_len_ptr);
    EVP_MAC_final(mctx, out, out_len_ptr, *out_len_ptr);


    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    OSSL_LIB_CTX_free(library_context);
    
    return out;
}

unsigned char* pkcs12_key_gen_raw(unsigned char* password, size_t password_len, unsigned char* salt, size_t salt_len, unsigned int id, unsigned int iteration, unsigned char *digest_name, size_t *out_len_ptr)
{
    unsigned char *out = NULL;
    const EVP_MD *digest;

    digest = EVP_get_digestbyname(digest_name);
    *out_len_ptr = EVP_MD_get_size(digest);

    out = OPENSSL_malloc(*out_len_ptr); 
    PKCS12_key_gen(password, password_len, salt, salt_len, id, iteration, *out_len_ptr, out, digest);

    return out;
}

unsigned char* pkcs5_pbkdf2_hmac_raw(unsigned char* password, size_t password_len, unsigned char *salt, size_t salt_len, unsigned int iteration, unsigned char *digest_name, size_t *out_len_ptr)
{
    unsigned char *out = NULL;
    const EVP_MD *digest;

    digest = EVP_get_digestbyname(digest_name);
    *out_len_ptr = EVP_MD_get_size(digest);


    out = OPENSSL_malloc(*out_len_ptr); 
    PKCS5_PBKDF2_HMAC(password, password_len, salt, salt_len, iteration, digest, *out_len_ptr, out);

    return out;
}

unsigned char* digest_raw(unsigned char* digest_name, unsigned char* msg, size_t msg_len, size_t *out_len_ptr)
{
    unsigned char *out = NULL;
    const EVP_MD *digest;

    digest = EVP_get_digestbyname(digest_name);
    *out_len_ptr = EVP_MD_get_size(digest);

    out = OPENSSL_malloc(*out_len_ptr); 
    EVP_Digest(msg, msg_len, out, (unsigned int *) out_len_ptr, digest, NULL);

    return out;
}

unsigned char* ecdh_raw(EVP_PKEY *priv, EVP_PKEY *peer_pub, size_t *z_len_ptr)
{
    unsigned char* z=NULL;
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new(priv, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pub);

    EVP_PKEY_derive(ctx, NULL, z_len_ptr);
    z = OPENSSL_malloc(*z_len_ptr);
    EVP_PKEY_derive(ctx, z, z_len_ptr);

    OPENSSL_free(ctx);

    return z;
}

unsigned char* ecdh_pem_raw(unsigned char* local_priv_pem, unsigned char* peer_pub_pem, size_t *z_len_ptr)
{

    EVP_PKEY *pkey = NULL;
    FILE *keyfile = fopen(local_priv_pem, "r");
    pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);

    EVP_PKEY *peer_pubkey = NULL;
    FILE *peer_pubkeyfile = fopen(peer_pub_pem, "r");
    peer_pubkey = PEM_read_PUBKEY(peer_pubkeyfile, NULL, NULL, NULL);

    unsigned char *z;
    z = ecdh_raw(pkey, peer_pubkey, z_len_ptr);

    return z;
}

EVP_PKEY * gen_ec_key(unsigned char *group_name, unsigned char* priv_hex)
{

    int nid;
    EVP_PKEY_CTX *ctx=NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[3];
    OSSL_PARAM *p = params;

    unsigned char* priv=NULL;
    size_t priv_len;
    BIGNUM *priv_bn = NULL;

    nid = OBJ_sn2nid(group_name);

    priv = OPENSSL_hexstr2buf(priv_hex, &priv_len);

    if(priv){
        pkey = EVP_PKEY_new_raw_private_key(nid, NULL, priv, priv_len);
    }else{
        ctx = EVP_PKEY_CTX_new_id(nid, NULL);
        if(ctx){
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_keygen(ctx, &pkey);
        }
    }

    if(pkey)
        return pkey;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0);

    if(priv){
        BN_hex2bn(&priv_bn, priv_hex);
        BN_bn2nativepad(priv_bn, priv, priv_len);
        *p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len);
        OPENSSL_free(priv_bn);
    }

    *p = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC",NULL);
    if(priv){
        EVP_PKEY_fromdata_init(ctx);
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params);
    }else{
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_params(ctx, params);
        EVP_PKEY_keygen(ctx, &pkey);
    }

    OPENSSL_free(ctx);
    OPENSSL_free(priv);

    return pkey;

}

EVP_PKEY * gen_ec_pubkey(unsigned char *group_name, unsigned char* point_hex)
{
    unsigned char *point; 
    size_t point_len;
    int nid;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;

    point = OPENSSL_hexstr2buf(point_hex, &point_len);

    nid = OBJ_sn2nid(group_name);

        pctx = EVP_PKEY_CTX_new_id(nid, NULL);
        if(pctx){
            pkey = EVP_PKEY_new_raw_public_key(nid, NULL, point, point_len);
            return pkey;
        }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_fromdata_init(pctx);

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *) group_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point, point_len);
    params[2] = OSSL_PARAM_construct_end();

    EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(point);

    return pkey;

}

unsigned char* write_key_to_pem(unsigned char* dst_fname, EVP_PKEY *pkey)
{
    BIO *out;
    out = BIO_new_file(dst_fname, "w+");

    PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);

    BIO_flush(out);

    return dst_fname;
}

unsigned char* write_pubkey_to_pem(unsigned char* dst_fname, EVP_PKEY *pkey)
{
    BIO *out;
    out = BIO_new_file(dst_fname, "w+");

    PEM_write_bio_PUBKEY(out, pkey);

    BIO_flush(out);

    return dst_fname;
}

int aead_encrypt_raw(unsigned char *cipher_name, unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char **ciphertext, unsigned char **tag, int tag_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        return -1;

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    *ciphertext = OPENSSL_malloc(plaintext_len);

    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    *tag = OPENSSL_malloc(tag_len);

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, *tag))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len, *tag))
            return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aead_decrypt_raw( unsigned char *cipher_name, unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char **plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        return -1;

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }
    
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    *plaintext = OPENSSL_malloc(ciphertext_len);

    if(!EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, tag))
            return -1;
    }

    ret = EVP_DecryptFinal_ex(ctx, *plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}

void print_pkey_gettable_params(EVP_PKEY *pkey)
{
    // https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-EC.html

    const OSSL_PARAM  *params, *p;
    params = EVP_PKEY_gettable_params(pkey);
    for (p = params; p->key != NULL; p++) {
        printf("%s\n", p->key);
    }

    return;
}


BIGNUM* get_pkey_bn_param(EVP_PKEY *pkey, unsigned char *param_name)
{
    BIGNUM *x_bn = NULL;

    x_bn = BN_new();
    EVP_PKEY_get_bn_param(pkey, param_name, &x_bn);

    return x_bn;
}

unsigned char* get_pkey_octet_string_param(EVP_PKEY *pkey, unsigned char *param_name)
{
    unsigned char *s, *s_hex;
    size_t s_len;
    
    EVP_PKEY_get_octet_string_param(pkey, param_name, NULL,  0, &s_len);
    s = OPENSSL_malloc(s_len);
    EVP_PKEY_get_octet_string_param(pkey, param_name, s, s_len, NULL);

    s_hex = bin2hex(s, s_len);
    
    return s_hex;
}

unsigned char* get_pkey_utf8_string_param(EVP_PKEY *pkey, unsigned char *param_name)
{
    unsigned char *s;
    size_t s_len;

    EVP_PKEY_get_utf8_string_param(pkey, param_name, NULL,  0, &s_len);
    s = OPENSSL_malloc(s_len);
    EVP_PKEY_get_utf8_string_param(pkey, param_name, s, s_len, NULL);

    return s;
}

EC_POINT* hex2point(EC_GROUP *group, unsigned char* point_hex)
  {
    BN_CTX *ctx = BN_CTX_new();

    EC_POINT* ec_point = EC_POINT_new(group);
    ec_point = EC_POINT_hex2point(group, point_hex, ec_point, ctx);

    BN_CTX_free(ctx);

    return  ec_point;
  }


MODULE = Crypt::OpenSSL::Base::Func		PACKAGE = Crypt::OpenSSL::Base::Func		

EVP_PKEY* evp_pkey_from_priv_hex(EC_GROUP* group, char* priv_hex)  

EVP_PKEY* evp_pkey_from_point_hex(EC_GROUP* group, char* point_hex, BN_CTX* ctx)  

unsigned char* export_pubkey(EVP_PKEY *priv_pkey)

EC_POINT* hex2point(EC_GROUP *group, unsigned char* point_hex)

EVP_PKEY * gen_ec_key(unsigned char *group_name, unsigned char* priv_hex)

EVP_PKEY * gen_ec_pubkey(unsigned char* group_name, unsigned char* point_hex)

EVP_PKEY* read_priv_pkey_from_pem(unsigned char *keyfile)

EVP_PKEY* read_pub_pkey_from_pem(unsigned char *keyfile)

char * bin2hex(const unsigned char * bin, size_t len)

unsigned char* bn_mod_sqrt(unsigned char *a, unsigned char *p)

unsigned char* read_ec_key(EVP_PKEY *priv_pkey)

unsigned char* read_ec_key_from_pem(unsigned char* keyfile) 

unsigned char* read_ec_pubkey(EVP_PKEY *pkey)

unsigned char* read_ec_pubkey_from_pem(char* keyfile) 

unsigned char* write_key_to_pem(unsigned char* dst_fname, EVP_PKEY *pkey)

unsigned char* write_pubkey_to_pem(unsigned char* dst_fname, EVP_PKEY *pkey)

BIGNUM* get_pkey_bn_param(EVP_PKEY *pkey, unsigned char *param_name)

unsigned char* get_pkey_octet_string_param(EVP_PKEY *pkey, unsigned char *param_name)

unsigned char* get_pkey_utf8_string_param(EVP_PKEY *pkey, unsigned char *param_name)

void print_pkey_gettable_params(EVP_PKEY *pkey)




int OBJ_sn2nid (const char *s)

EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey)

const EVP_MD *EVP_get_digestbyname(const char *name)

int EVP_MD_get_block_size(const EVP_MD *md)

int EVP_MD_get_size(const EVP_MD *md)

int EC_GROUP_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx)

int EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)

int EC_POINT_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)



SV* aes_cmac(unsigned char* cipher_name, SV* key_sv, SV* msg_sv)
    CODE:
    {
    unsigned char *key= NULL;
    size_t key_len;
    unsigned char *msg= NULL;
    size_t msg_len;
    unsigned char* out = NULL;
    size_t out_len;

    key = (unsigned char*) SvPV( key_sv, key_len );
    msg = (unsigned char*) SvPV( msg_sv, msg_len );

    out = aes_cmac_raw(cipher_name, key, key_len, msg, msg_len, &out_len);

    RETVAL = newSVpv(out, out_len);

    }
    OUTPUT:
        RETVAL

SV* pkcs12_key_gen(SV* password_sv, SV* salt_sv, unsigned int id, unsigned int iteration, unsigned char* digest_name)
    CODE:
    {
    unsigned char *password= NULL;
    size_t password_len;
    unsigned char *salt= NULL;
    size_t salt_len;
    unsigned char* out = NULL;
    size_t out_len;

    password = (unsigned char*) SvPV( password_sv, password_len );
    salt = (unsigned char*) SvPV( salt_sv, salt_len );

    out = pkcs12_key_gen_raw(password, password_len, salt, salt_len, id, iteration, digest_name, &out_len);

    RETVAL = newSVpv(out, out_len);

    }
    OUTPUT:
        RETVAL

SV* pkcs5_pbkdf2_hmac(SV* password_sv, SV* salt_sv, unsigned int iteration, unsigned char* digest_name)
    CODE:
    {
    unsigned char *password= NULL;
    size_t password_len;
    unsigned char *salt= NULL;
    size_t salt_len;
    unsigned char* out = NULL;
    size_t out_len;

    password = (unsigned char*) SvPV( password_sv, password_len );
    salt = (unsigned char*) SvPV( salt_sv, salt_len );

    out = pkcs5_pbkdf2_hmac_raw(password, password_len, salt, salt_len, iteration, digest_name, &out_len);

    RETVAL = newSVpv(out, out_len);

    }
    OUTPUT:
        RETVAL

SV* digest(unsigned char *digest_name, SV* msg_SV)
  CODE:
  {
    unsigned char *msg= NULL;
    size_t msg_len;
    unsigned char* out = NULL;
    size_t out_len;

    msg = (unsigned char*) SvPV( msg_SV, msg_len );

    out = digest_raw(digest_name, msg, msg_len, &out_len);

    RETVAL = newSVpv(out, out_len);
  }
  OUTPUT:
    RETVAL

SV* ecdh(EVP_PKEY *priv, EVP_PKEY *peer_pub)
  CODE:
  {
    unsigned char* out = NULL;
    size_t out_len;

    out = ecdh_raw(priv, peer_pub, &out_len);

    RETVAL = newSVpv(out, out_len);
  }
  OUTPUT:
    RETVAL

SV* ecdh_pem(unsigned char* local_priv_pem, unsigned char* peer_pub_pem)
  CODE:
  {
    unsigned char* out = NULL;
    size_t out_len;

    out = ecdh_pem_raw(local_priv_pem, peer_pub_pem, &out_len);

    RETVAL = newSVpv(out, out_len);
  }
  OUTPUT:
    RETVAL

SV* aead_encrypt(unsigned char* cipher_name, SV* plaintext_SV, SV* aad_SV, SV* key_SV, SV* iv_SV, int tag_len)
  CODE:
    {
    unsigned char *plaintext;
    size_t plaintext_len;
    unsigned char *aad;
    size_t aad_len;
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;

    unsigned char *ciphertext;
    size_t ciphertext_len;
    SV* ciphertext_SV ;
    SV* tag_SV ;
    unsigned char *tag;

    AV* av = newAV();

    plaintext = (unsigned char*) SvPV( plaintext_SV, plaintext_len );
    aad = (unsigned char*) SvPV( aad_SV, aad_len );
    key = (unsigned char*) SvPV( key_SV, key_len );
    iv = (unsigned char*) SvPV( iv_SV, iv_len );

    ciphertext_len = aead_encrypt_raw(cipher_name, plaintext, plaintext_len, aad, aad_len, key, iv, iv_len, &ciphertext, &tag, tag_len);

    ciphertext_SV = newSVpv(ciphertext, ciphertext_len);
    tag_SV = newSVpv(tag, tag_len);

    av_push(av, ciphertext_SV);
    av_push(av, tag_SV);

    RETVAL = newRV_noinc((SV*)av);

    /*int nid = OBJ_sn2nid(group_name);*/
    /*SV* nid_sv = newSViv(nid);*/
    /*SV* group_name_sv = newSVpv(group_name, strlen(group_name));*/

    /*hv = newHV ();*/
    /*hv_store (hv, "nid", strlen ("nid"), nid_sv, 0);*/
    /*hv_store (hv, "group_name", strlen ("group_name"), group_name_sv , 0);*/
    /*RETVAL = newRV_inc ((SV *) hv);*/

    }
      OUTPUT:
        RETVAL

SV* aead_decrypt(unsigned char* cipher_name, SV* ciphertext_SV, SV* aad_SV, SV* tag_SV, SV* key_SV, SV* iv_SV)
  CODE:
{
    SV *res;
    unsigned char *plaintext;
    size_t plaintext_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *aad;
    size_t aad_len;
    unsigned char *tag;
    size_t tag_len;
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;

    ciphertext = (unsigned char*) SvPV( ciphertext_SV, ciphertext_len );
    aad = (unsigned char*) SvPV( aad_SV, aad_len );
    tag = (unsigned char*) SvPV( tag_SV, tag_len );
    key = (unsigned char*) SvPV( key_SV, key_len );
    iv = (unsigned char*) SvPV( iv_SV, iv_len );

    plaintext_len = aead_decrypt_raw(cipher_name, ciphertext, ciphertext_len, aad, aad_len, tag, tag_len, key, iv, iv_len, &plaintext);

    res = newSVpv(plaintext, plaintext_len);

    RETVAL = res;
}
  OUTPUT:
    RETVAL


