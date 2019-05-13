#ifndef _APP_PARAMS_H
#define _APP_PARAMS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _params
{
	char* port;
	char* app_mode;
	char* output_file;
	int hash_option;
	int sketch_mode;
	int sketch_width;
	int sketch_depth;
	int sketch_rup;
	int sketch_cand_only;
	uint32_t num_files;
	uint32_t num_files_case;
	uint32_t chunk_size;
	int k;
	int l;
	int num_pc;
	float eps;
} app_parameters;

void init_app_params(app_parameters**);
void print_app_params(app_parameters*);

#ifdef __cplusplus
};
#endif

#endif
