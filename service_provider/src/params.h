#ifndef _PARAMS_H
#define _PARAMS_H

typedef struct _params
{
	char* port;
	char* app_mode;
	char* vcf_dir;
	char* snp_ids;
	int num_files;
} parameters;

void init_params(parameters**);
void print_params(parameters*);

#endif
