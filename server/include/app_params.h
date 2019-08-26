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
	int num_buckets;
	int init_capacity;
	int sketch_mode;
	int sketch_width;
	int sketch_depth;
	int sketch_cand_only;
	uint32_t num_files;
	uint32_t num_files_case;
	uint32_t num_cases;
	uint32_t num_controls;
	uint32_t chunk_size;
	int k;
	int l;
	int num_pc;
	float eps;
	int num_threads;
	int cache;
	int debug;
} app_parameters;

void init_app_params(app_parameters**);
void print_app_params(app_parameters*);

#ifdef __cplusplus
};
#endif

#endif
