#ifndef _SP_PARAMS_H
#define _SP_PARAMS_H

#include <stdint.h>

typedef struct _params
{
	char* port;
	char* app_mode;
	char* vcf_dir;
	char* snp_ids;
	uint32_t num_files;
	uint32_t chunk_size;
} parameters;

void init_params(parameters**);
void print_params(parameters*);

#endif
