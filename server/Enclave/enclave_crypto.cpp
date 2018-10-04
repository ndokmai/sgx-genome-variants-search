#include <string.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <openssl/evp.h>
#include "Enclave_t.h"

uint8_t sk[16];

void enclave_derive_key(sgx_ra_context_t ctx)
{
    sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, (sgx_ra_key_128_t *)sk);
}

void enclave_getkey(uint8_t *key) 
{
    memcpy(key, sk, 16);
}

int enclave_decrypt_internal(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

int enclave_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext) 
{
    unsigned char iv[16];
    memcpy(iv, ciphertext, 16);
    ciphertext += 16;
    ciphertext_len -= 16;
    size_t plen = enclave_decrypt_internal(ciphertext, ciphertext_len, key, iv, plaintext);
    return plen;
}

int enclave_decrypt_internal(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 128 bit AES (i.e. a 128 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;

}
