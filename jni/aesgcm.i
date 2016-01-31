/* sodium.i */
%module Sodium

%include "typemaps.i"
%include "stdint.i"
%include "arrays_java.i"
%include "carrays.i"
%include "various.i"

/* Basic mappings */
%apply int {unsigned long long};
%apply long[] {unsigned long long *};
%apply int {size_t};
%apply int {uint32_t};
%apply long {uint64_t};

/* unsigned char */
%typemap(jni) unsigned char *"jbyteArray"
%typemap(jtype) unsigned char *"byte[]"
%typemap(jstype) unsigned char *"byte[]"
%typemap(in) unsigned char *{
    $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) unsigned char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) unsigned char *"$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char *""

/* const uchar */
%typemap(jni) const uchar *"jbyteArray"
%typemap(jtype) const uchar *"byte[]"
%typemap(jstype) const uchar *"byte[]"
%typemap(in) const uchar *{
    $1 = (const uchar *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) const uchar *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) const uchar *"$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) const uchar *""



/* uint8_t */
%typemap(jni) uint8_t *"jbyteArray"
%typemap(jtype) uint8_t *"byte[]"
%typemap(jstype) uint8_t *"byte[]"
%typemap(in) uint8_t *{
    $1 = (uint8_t *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) uint8_t *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) uint8_t *"$javainput"
%typemap(freearg) uint8_t *""

/* String return values, from *_primitive methods */
%typemap(jni) const char *"jstring"
%typemap(jtype) const char *"String"
%typemap(jstype) const char *"String"

/* Strings */
%typemap(jni) char *"jbyteArray"
%typemap(jtype) char *"byte[]"
%typemap(jstype) char *"byte[]"
%typemap(in) char *{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *"$javainput"
%typemap(freearg) char *""


/* char types */
%typemap(jni) char *BYTE "jbyteArray"
%typemap(jtype) char *BYTE "byte[]"
%typemap(jstype) char *BYTE "byte[]"
%typemap(in) char *BYTE {
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *BYTE {
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *BYTE "$javainput"
%typemap(freearg) char *BYTE ""

/* Fixed size strings/char arrays */
%typemap(jni) char [ANY]"jbyteArray"
%typemap(jtype) char [ANY]"byte[]"
%typemap(jstype) char [ANY]"byte[]"
%typemap(in) char [ANY]{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char [ANY]{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char [ANY]"$javainput"
%typemap(freearg) char [ANY]""



/* *****************************************************************************

    HIGH-LEVEL LIBSODIUM API'S

***************************************************************************** */


%{
#include "sodium.h"
%}

/*
    Runtime API
*/
int sodium_init(void);

const char *sodium_version_string(void);

/* void randombytes(unsigned char * const buf, const unsigned long long buf_len); */
void randombytes(unsigned char *dst_buf,
                 unsigned long long buf_len);

/*
    randombytes API
*/
uint32_t randombytes_random(void);

uint32_t randombytes_uniform(const uint32_t upper_bound);

/*void randombytes_buf(void * const buf, const size_t size);*/
void randombytes_buf(unsigned char * const buff,
                     const unsigned long long buff_len);

int randombytes_close(void);

void randombytes_stir(void);

/*
    helpers API
*/
/*int sodium_memcmp(const void * const b1_,
                  const void * const b2_,
                  size_t len);*/

void sodium_increment(unsigned char *src_dst_number,
                      const size_t number_len);
					  
/* =============================================================================

    TYPEMAPS FOR gcm_context

============================================================================= */

/*
    gcm_context
*/
%typemap(jni) gcm_context *"jbyteArray"
%typemap(jtype) gcm_context *"byte[]"
%typemap(jstype) gcm_context *"byte[]"
%typemap(in) gcm_context{
    $1 = (gcm_context *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) gcm_context *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) gcm_context *"$javainput"
%typemap(freearg) gcm_context *""


/*
    aes_context
*/
%typemap(jni) aes_context *"jbyteArray"
%typemap(jtype) aes_context *"byte[]"
%typemap(jstype) aes_context *"byte[]"
%typemap(in) aes_context{
    $1 = (aes_context *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) aes_context *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) aes_context *"$javainput"
%typemap(freearg) aes_context *""


/* =============================================================================

Begin Steves AES translation

============================================================================= */


%{
#include "aes.h"
#include "gcm.h"
%}

/*
	AES encryption

*/
int aes_setkey( aes_context *ctx,       // pointer to context
                int mode,               // 1 or 0 for Encrypt/Decrypt
                const uchar *key,       // AES input key
                uint keysize );         // 128, 192 or 256 bits
                                        // returns 0 for success
										
int aes_cipher( aes_context *ctx,       // pointer to context
                const uchar input[16],  // 128-bit block to en/decipher
                uchar output[16] );     // 128-bit output result block
                                        // returns 0 for success										

/* 
	GCM Support
*/

int gcm_setkey( gcm_context *ctx,   // caller-provided context ptr
                const uchar *key,   // pointer to cipher key
                const uint keysize  // must be 128, 192 or 256
); // returns 0 for success


int gcm_crypt_and_tag(
        gcm_context *ctx,       // gcm context with key already setup
        int mode,               // cipher direction: GCM_ENCRYPT or GCM_DECRYPT
        const uchar *iv,        // pointer to the 12-byte initialization vector
        size_t iv_len,          // byte length if the IV. should always be 12
        const uchar *add,       // pointer to the non-ciphered additional data
        size_t add_len,         // byte length of the additional AEAD data
        const uchar *input,     // pointer to the cipher data source
        uchar *output,          // pointer to the cipher data destination
        size_t length,          // byte length of the cipher data
        uchar *tag,             // pointer to the tag to be generated
        size_t tag_len );       // byte length of the tag to be generated
		
int gcm_auth_decrypt(
        gcm_context *ctx,       // gcm context with key already setup
        const uchar *iv,        // pointer to the 12-byte initialization vector
        size_t iv_len,          // byte length if the IV. should always be 12
        const uchar *add,       // pointer to the non-ciphered additional data
        size_t add_len,         // byte length of the additional AEAD data
        const uchar *input,     // pointer to the cipher data source
        uchar *output,          // pointer to the cipher data destination
        size_t length,          // byte length of the cipher data
        const uchar *tag,       // pointer to the tag to be authenticated
        size_t tag_len );       // byte length of the tag <= 16
		
int gcm_start( gcm_context *ctx,    // pointer to user-provided GCM context
               int mode,            // GCM_ENCRYPT or GCM_DECRYPT
               const uchar *iv,     // pointer to initialization vector
               size_t iv_len,       // IV length in bytes (should == 12)
               const uchar *add,    // pointer to additional AEAD data (NULL if none)
               size_t add_len );    // length of additional AEAD data (bytes)	

int gcm_update( gcm_context *ctx,       // pointer to user-provided GCM context
                size_t length,          // length, in bytes, of data to process
                const uchar *input,     // pointer to source data
                uchar *output );        // pointer to destination data
				
int gcm_finish( gcm_context *ctx,   // pointer to user-provided GCM context
                uchar *tag,         // ptr to tag buffer - NULL if tag_len = 0
                size_t tag_len );   // length, in bytes, of the tag-receiving buf				



/*
    PW-Hash scryptsalsa208sha256
*/
size_t crypto_pwhash_scryptsalsa208sha256_saltbytes(void);

size_t crypto_pwhash_scryptsalsa208sha256_strbytes(void);
const char *crypto_pwhash_scryptsalsa208sha256_strprefix(void);

size_t crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(void);
size_t crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);

int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                       unsigned long long outlen,
                                       const char * const passwd,
                                       unsigned long long passwdlen,
                                       const unsigned char * const salt,
                                       unsigned long long opslimit,
                                       size_t memlimit);

int crypto_pwhash_scryptsalsa208sha256_str(char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                           const char * const passwd,
                                           unsigned long long passwdlen,
                                           unsigned long long opslimit,
                                           size_t memlimit);

int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                                  const char * const passwd,
                                                  unsigned long long passwdlen);

int crypto_pwhash_scryptsalsa208sha256_ll(const uint8_t * passwd,
                                          size_t passwdlen,
                                          const uint8_t * salt,
                                          size_t saltlen,
                                          uint64_t N,
                                          uint32_t r,
                                          uint32_t p,
                                          uint8_t * buf,
                                          size_t buflen);
/*
    crypto_sign API
*/
size_t crypto_sign_bytes(void);
size_t crypto_sign_seedbytes(void);
size_t crypto_sign_publickeybytes(void);
size_t crypto_sign_secretkeybytes(void);

const char *crypto_sign_primitive(void);

int crypto_sign_keypair(unsigned char *dst_public_Key,
                        unsigned char *dst_private_key);

int crypto_sign_seed_keypair(unsigned char *dst_public_Key,
                             unsigned char *dst_private_key,
                             const unsigned char *src_seed);

int crypto_sign(unsigned char *dst_signed_msg,
                unsigned long long *signed_msg_len,
                const unsigned char *src_msg,
                unsigned long long msg_len,
                const unsigned char *local_private_key);

int crypto_sign_open(unsigned char *dst_msg,
                     unsigned long long *msg_len,
                     const unsigned char *src_signed_msg,
                     unsigned long long signed_msg_len,
                     const unsigned char *remote_public_key);

int crypto_sign_detached(unsigned char *dst_signature,
                         unsigned long long *signature_len,
                         const unsigned char *src_msg,
                         unsigned long long msg_len,
                         const unsigned char *local_private_key);

int crypto_sign_verify_detached(const unsigned char *src_signature,
                                const unsigned char *src_msg,
                                unsigned long long msg_len,
                                const unsigned char *remote_public_key);

int crypto_sign_ed25519_sk_to_seed(unsigned char *dst_seed,
                                   const unsigned char *src_private_key);

int crypto_sign_ed25519_sk_to_pk(unsigned char *dst_public_key,
                                 const unsigned char *src_private_key);



/*
    Box Curve25519XSalsa20Poly1305
*/

size_t crypto_box_curve25519xsalsa20poly1305_seedbytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_publickeybytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_secretkeybytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_beforenmbytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_noncebytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_zerobytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_boxzerobytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_macbytes(void);

int crypto_box_curve25519xsalsa20poly1305(unsigned char *c,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *n,
                                          const unsigned char *pk,
                                          const unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_open(unsigned char *m,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *n,
                                               const unsigned char *pk,
                                               const unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_seed_keypair(unsigned char *pk,
                                                       unsigned char *sk,
                                                       const unsigned char *seed);

int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                                  unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_beforenm(unsigned char *k,
                                                   const unsigned char *pk,
                                                   const unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_afternm(unsigned char *c,
                                                  const unsigned char *m,
                                                  unsigned long long mlen,
                                                  const unsigned char *n,
                                                  const unsigned char *k);

int crypto_box_curve25519xsalsa20poly1305_open_afternm(unsigned char *m,
                                                       const unsigned char *c,
                                                       unsigned long long clen,
                                                       const unsigned char *n,
                                                       const unsigned char *k);
													   
													   /*
    ScalarMult Curve25519
*/
size_t crypto_scalarmult_curve25519_bytes(void);
size_t crypto_scalarmult_curve25519_scalarbytes(void);

int crypto_scalarmult_curve25519(unsigned char *q,
                                 const unsigned char *n,
                                 const unsigned char *p);
int crypto_scalarmult_curve25519_base(unsigned char *q,
                                      const unsigned char *n);


int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                         const unsigned char *ed25519_sk);

int crypto_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk);

int crypto_sign_ed25519_sk_to_pk(unsigned char *pk,
                                 const unsigned char *sk);