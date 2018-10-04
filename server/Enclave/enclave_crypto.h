#ifndef __ENCLAVE_CRYPTO_H
#define __ENCLAVE_CRYPTO_H

#include <sgx_tae_service.h>

void enclave_derive_key(sgx_ra_context_t ctx);
void enclave_getkey(uint8_t *key);

int enclave_decrypt(unsigned char *ciphertext, 
        int ciphertext_len, 
        unsigned char *key, 
        unsigned char *plaintext);

#endif
