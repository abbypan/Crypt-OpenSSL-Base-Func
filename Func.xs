#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define PACKAGE_NAME "Crypt::OpenSSL::Base::Func"


MODULE = Crypt::OpenSSL::Base::Func		PACKAGE = Crypt::OpenSSL::Base::Func
PROTOTYPES: DISABLE

unsigned char*
aes_cmac(key_hexstr, msg_hexstr, cipher_name)
    unsigned char *key_hexstr;
    unsigned char *msg_hexstr;
    unsigned char *cipher_name;
  PREINIT:
    unsigned char *mac_hexstr;
  CODE:
{
  long key_len;
  unsigned char *key = OPENSSL_hexstr2buf(key_hexstr, &key_len);
  
  long msg_len;
  unsigned char *msg = OPENSSL_hexstr2buf(msg_hexstr, &msg_len);

 const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
 
 size_t block_size = EVP_CIPHER_block_size(cipher);

 unsigned char *mact = OPENSSL_malloc(block_size); 

  CMAC_CTX *ctx = CMAC_CTX_new();
  CMAC_Init(ctx, key, block_size, cipher, NULL);
 
  CMAC_Update(ctx, msg, msg_len);
  CMAC_Final(ctx, mact, &block_size);

  CMAC_CTX_free(ctx);

  unsigned char* mac_hexstr = OPENSSL_buf2hexstr(mact, block_size);

    OPENSSL_free(key);
    OPENSSL_free(msg);
    OPENSSL_free(mact);

    RETVAL = mac_hexstr;
}
  OUTPUT:
    RETVAL 


unsigned char*
ecdh(local_priv_pem, peer_pub_pem)
    unsigned char *local_priv_pem;
    unsigned char *peer_pub_pem;
  PREINIT:
    unsigned char *z_hexstr;
  CODE:
{

    FILE *keyfile = fopen(local_priv_pem, "r");
    EVP_PKEY *pkey = NULL;
    pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    //printf("\nRead Local Private Key:\n");
    //PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);

    FILE *peer_pubkeyfile = fopen(peer_pub_pem, "r");
    EVP_PKEY *peer_pubkey = NULL;
    peer_pubkey = PEM_read_PUBKEY(peer_pubkeyfile, NULL, NULL, NULL);
    //printf("\nRead Peer PUBKEY Key:\n");
    //PEM_write_PUBKEY(stdout, peer_pubkey);


    EVP_PKEY_CTX *ctx;
    unsigned char *z;
    size_t zlen;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    EVP_PKEY_derive_init(ctx);

    EVP_PKEY_derive_set_peer(ctx, peer_pubkey);

    EVP_PKEY_derive(ctx, NULL, &zlen);

    z = OPENSSL_malloc(zlen);

    EVP_PKEY_derive(ctx, z, &zlen);

    unsigned char* z_hexstr = OPENSSL_buf2hexstr(z, zlen);

    OPENSSL_free(z);

    RETVAL = z_hexstr;
}
  OUTPUT:
    RETVAL 
