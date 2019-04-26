#ifndef _SP_PARAMS_H
#define _SP_PARAMS_H

typedef struct _params
{
	char* port;
	char* app_mode;
	char* vcf_dir;
	char* snp_ids;
	int num_files;
	int chunk_size;
} parameters;

void init_params(parameters**);
void print_params(parameters*);

#endif
