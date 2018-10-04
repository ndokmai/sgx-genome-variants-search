#ifndef __RA_H
#define __RA_H

#include <cstdint>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include "msgio.h"

typedef struct config_struct {
    char mode;
    uint32_t flags;
    sgx_spid_t spid;
    sgx_ec256_public_t pubkey;
    sgx_quote_nonce_t nonce;
    char *server;
    char *port;
    sgx_enclave_id_t eid;
    sgx_ra_context_t ra_ctx;
    sgx_status_t sgxrv;
} config_t;

int parse_config(int argc, char *argv[], config_t& config);
int remote_attestation(config_t& config, MsgIO **_msgio);
void finalize(MsgIO* msgio, config_t& config);

#endif
