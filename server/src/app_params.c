#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "app_params.h"

void init_app_params(app_parameters** params)
{
	*params = (app_parameters*) malloc(sizeof(app_parameters));
	(*params)->port = NULL;
	(*params)->app_mode = NULL;
	(*params)->output_file = NULL;
	(*params)->num_files = 0;
	(*params)->num_files_case = 0;
	(*params)->num_cases = 0;
	(*params)->num_controls = 0;
	(*params)->chunk_size = 500000;
	(*params)->k = 100;
	(*params)->num_buckets = (1 << 21);
	(*params)->init_capacity = (1 << 23);
	(*params)->hash_option = 1;
	(*params)->sketch_mode = 1;
	(*params)->sketch_width = (1 << 18);
	(*params)->sketch_depth = 12;
	(*params)->l = (1 << 17);
	(*params)->sketch_cand_only = 0;
	(*params)->num_pc = 2;
	(*params)->eps = 0.12;
	(*params)->num_threads = 1;
}

void print_app_params(app_parameters* params)
{
	fprintf(stderr, "%-30s%s\n","PORT:", params->port);
	fprintf(stderr, "%-30s%s\n","APP_MODE:", params->app_mode);
	fprintf(stderr, "%-30s%u\n","NUM_FILES:", params->num_files);
	fprintf(stderr, "%-30s%u\n","NUM_CASE_FILES:", params->num_files_case);
	fprintf(stderr, "%-30s%u\n","CHUNK_SIZE:", params->chunk_size);
	fprintf(stderr, "%-30s%d\n","NUM_TOP_SNPS:", params->k);
	fprintf(stderr, "%-30s%s\n","OUTPUT_FILE:", params->output_file);
	if(strcmp(params->app_mode, "basic") == 0)
	{
		switch(params->hash_option)
		{
			case 0:
				fprintf(stderr, "%-30s%s\n","HASH_OPTION:", "oa");
				fprintf(stderr, "%-30s%d\n","INIT_CAPACITY:", params->init_capacity);
				break;
			case 2:
				fprintf(stderr, "%-30s%s\n","HASH_OPTION:", "cmtf");
				fprintf(stderr, "%-30s%d\n","NUM_BUCKETS:", params->num_buckets);
				break;
			default:
				fprintf(stderr, "%-30s%s\n","HASH_OPTION:", "rhht");
				fprintf(stderr, "%-30s%d\n","INIT_CAPACITY:", params->init_capacity);
				break;
		}
	}
	if(strcmp(params->app_mode, "sketch") == 0)
	{
		switch(params->sketch_mode)
		{
			case 0:
				fprintf(stderr, "%-30s%s\n","SKETCH_MODE:", "cms");
				break;
			default:
				fprintf(stderr, "%-30s%s\n","SKETCH_MODE:", "csk");
				break;
		}
		fprintf(stderr, "%-30s%d\n","NUM_TOP_CAND:", params->l);
		fprintf(stderr, "%-30s%d\n","SKETCH_WIDTH:", params->sketch_width);
		fprintf(stderr, "%-30s%d\n","SKETCH_DEPTH:", params->sketch_depth);
		fprintf(stderr, "%-30s%d\n","SKETCH_CAND_ONLY:", params->sketch_cand_only);
	}
	
}
