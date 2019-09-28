#ifndef __RA_H
#define __RA_H

#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "msgio.h"
#include "iasrequest.h"

typedef struct config_struct {
	sgx_spid_t spid;
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	char *proxy_server;
	char *ca_bundle;
	char *user_agent;
	char *cert_file;
	char *cert_key_file;
	char *cert_passwd_file;
	unsigned int proxy_port;
	unsigned char kdk[16];
	char *cert_type[4];
	X509_STORE *store;
	X509 *signing_ca;
	unsigned int apiver;
	char *sigrl;
	char *port;
        char flag_prod;
	char flag_noproxy;
        char flag_stdio;
	int oops;
        IAS_Connection *ias;
} config_t;

int parse_config(int argc, char *argv[], config_t &config);
int connect_no_ra(config_t &config, MsgIO **msgio);
int connect(config_t &config, MsgIO **msgio);
int remote_attestation(config_t &config, MsgIO *msgio);
void finalize(MsgIO* msgio, config_t &config);

#endif
