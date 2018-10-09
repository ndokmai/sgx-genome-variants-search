#include <stdlib.h>
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include "config.h"
#include "Enclave_t.h"
#include "enclave_crypto.h"

#define	MAX_BUF_LEN	4 * 1024 * 1024

uint8_t enclave_buffer[MAX_BUF_LEN];
uint64_t sum;

void enclave_init_sum()
{
	sum = 0;
}

void enclave_get_result(uint64_t* result)
{
	memcpy(result, &sum, sizeof(uint64_t));
}

void enclave_out_function(char *buf, size_t len)
{
    if(len <= (size_t) MAX_BUF_LEN) {
        memcpy(buf,enclave_buffer,len);
    } 
}

int enclave_decrypt_for_me(sgx_ra_context_t ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, uint8_t* _sk)
{
    uint8_t sk[16];
    enclave_getkey(sk);
    // This is done to print out the key. In the real use key sk should not be leaked from the enclave.
    memcpy(_sk, sk, 16);
    size_t plen = enclave_decrypt(ciphertext, ciphertext_len, sk, plaintext);
    return plen;
}

void enclave_decrypt_process(sgx_ra_context_t ctx, uint8_t* ciphertext, size_t ciphertext_len)
{
	// Buffer to hold the secret key
    uint8_t sk[16];

	// Buffer to hold the decrypted plaintext
	// Plaintext length can't be longer than the ciphertext length
	uint8_t* plaintext = new uint8_t[ciphertext_len];

	// Internal Enclave function to fetch the secret key
    enclave_getkey(sk);

	// Decrypt the ciphertext, place it inside the plaintext buffer and return the length of the plaintext
    size_t plaintext_len = enclave_decrypt(ciphertext, ciphertext_len, sk, plaintext);

	// Process data
	for(size_t i = 0; i < plaintext_len / 4; i++)
	{
		sum = sum + ((uint32_t*) plaintext)[i];
	}

	// We've processed the data, now clear it
	delete[] plaintext;
}
