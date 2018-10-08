#include <stdlib.h>
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include "config.h"
#include "Enclave_t.h"
#include "enclave_crypto.h"

#define MAX_BUF_LEN 2*1024*1024 
uint8_t enclave_buffer[MAX_BUF_LEN];
size_t buffer_size;
long magic_num = 1234;
long *sum;

void init_sum_magic()
{
    sum = (long*)malloc(sizeof(long));
    *sum = 0;
}

void sum_magic() 
{
    for(size_t i=0; i<buffer_size; i++) {
        *sum += (long)(enclave_buffer[i]);
    }
}

void finalize_sum_magic(long * result)
{
    *sum += magic_num;
    memcpy(result, sum, sizeof(*result));
    free(sum);
}

void enclave_out_function(char *buf, size_t len)
{
    if(len <= (size_t) MAX_BUF_LEN) {
        memcpy(buf,enclave_buffer,len);
    } 
}

void enclave_in_function(char *buf, size_t len)
{
    if(len <= (size_t)MAX_BUF_LEN) {
        memcpy(enclave_buffer,buf,len);
        buffer_size = len;
    }
}

int enclave_decrypt_for_me(sgx_ra_context_t ctx, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, 
        uint8_t* _sk)
{
    uint8_t sk[16];
    enclave_getkey(sk);
    // This is done to print out the key. In the real use key sk should not be leaked from the enclave.
    memcpy(_sk, sk, 16);
    size_t plen = enclave_decrypt(ciphertext, ciphertext_len, sk, plaintext);
    return plen;
}

// Put this in the edl
/*
void enclave_decrypt_safe(sgx_ra_context_t ctx, unsigned char* ciphertext, int ciphertext_len)
{
    uint8_t sk[16];

	uint8_t* plaintext = new uint8_t[ciphertext_len];

    enclave_getkey(sk);
    memcpy(_sk, sk, 16);

    size_t plen = enclave_decrypt(ciphertext, ciphertext_len, sk, plaintext);

	delete[] plaintext;
}
*/
