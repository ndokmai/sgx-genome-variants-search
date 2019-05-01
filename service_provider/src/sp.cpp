#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include "ra.h"
#include "msgio.h"
#include "misc.h"
#include "sp_params.h"
#include "crypto.h"
#include "fileio.h"
#include "config.h"
#include "settings.h"
#include "hexutil.h"
#include "logfile.h"

#define	MAX_FNAME	96

static const unsigned char def_service_private_key[32] = {
    0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
    0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
    0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
    0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

int parse(char* process_name, char* port, config_t &config)
{
	// call the script to generate args file
	system("./get_args_from_settings.sh");

	// parse args file
	std::vector<std::string> data{};
	data.push_back(std::string(process_name) + "\0");
	std::ifstream args("_args_");
	std::string line;
	std::getline(args, line);
	std::stringstream lineStream(line);
	std::string value;
	while(lineStream >> value)
	{
		value += "\0";
		data.push_back(value);
	}

	// add port at the end
	if(port != NULL) 
	{
		data.push_back(std::string(port) + "\0");
	}

	auto ra_argv = new char*[data.size()];
	for(size_t i=0; i<data.size(); i++) 
	{
		ra_argv[i] = data.at(i).data();
	}
	auto ra_argc = data.size();

	parse_config(ra_argc, ra_argv, config);
	delete[] ra_argv;

	// clean up the args file 
	system("rm _args_");
}

void send_encrypted_vcf(MsgIO* msgio, uint32_t num_files, uint32_t chunk_size, int index[], char filenames[][MAX_FNAME])
{
	struct stat st;

	for(uint32_t i = 0; i < num_files; i++)
	{
		if(stat(filenames[index[i]], &st) != -1)
		{
			// Open input binary file for reading
			FILE* file = fopen(filenames[index[i]], "rb");
			if(file == NULL)
			{
				fprintf(stderr, "Error opening file\n");
			}
			fprintf(stderr, "Filename: %s\n", filenames[index[i]]);

			// Move the file pointer to the end of the file
			fseek(file, 0, SEEK_END);

			// Get the size of the file (in bytes)
			uint32_t file_size = (uint32_t) ftell(file);
			//fprintf(stderr, "\tSize of file: %d bytes.\n", file_size);

			// Move the file pointer back to the beginning of the file
			rewind(file);

			// Each element in the file should be a 32-bit unsigned integer
			// Therefore we can calculate the total number of elements to be sent for the file
			uint32_t num_elems = file_size / sizeof(uint32_t);

			// Allocate memory for the file contents
			uint32_t* contents = (uint32_t*) malloc(sizeof(uint32_t) * num_elems);
			if(contents == NULL)
			{
				fprintf(stderr, "Error: malloc() failed ...\n");
			}
			
			// Read the file contents
			uint32_t elems_read = fread(contents, sizeof(uint32_t), num_elems, file);
			if(elems_read != num_elems)
			{
				fprintf(stderr, "Error: elems_read (%d) != num_elems (%d) ...\n", elems_read, num_elems);
			}
			
			// First send the file size
			auto num_elems_buf = new uint32_t[1];
			num_elems_buf[0] = num_elems;
			msgio->send_bin(num_elems_buf, sizeof(uint32_t));

			// Now send the actual file contents
			uint32_t num_elems_rem = num_elems;
			uint32_t num_elems_sent = 0;
			while(num_elems_sent != num_elems)
			{
				uint32_t to_send_elems = 0;
				if(num_elems_rem < chunk_size)
				{	
					to_send_elems = num_elems_rem;
				}
				else
				{
					to_send_elems = chunk_size;
				}
				msgio->send_bin_encrypted(contents + num_elems_sent, to_send_elems * sizeof(uint32_t));
				num_elems_sent = num_elems_sent + to_send_elems;
				num_elems_rem = num_elems_rem - to_send_elems;
			}

			// Close file
			fclose(file);

			// Free memory
			free(contents);
			delete[] num_elems_buf;
		}
	}
}

void send_encrypted_snpid(MsgIO* msgio, uint32_t chunk_size, char *uniq_snps_filename)
{
	FILE* uniq_snps = fopen(uniq_snps_filename, "rb");
	
	if(uniq_snps == NULL)
	{
		fprintf(stderr, "Error opening file\n");
	}

	// Move the file pointer to the end of the file
	fseek(uniq_snps, 0, SEEK_END);

	// Get the size of the file (in bytes)
	uint32_t file_size = (uint32_t) ftell(uniq_snps);
	//fprintf(stderr, "\tSize of file: %d bytes.\n", file_size);

	// Move the file pointer back to the beginning of the file
	rewind(uniq_snps);

	// Each element in the file should be a 32-bit unsigned integer
	// Therefore we can calculate the total number of elements to be sent for the file
	uint32_t num_elems = file_size / sizeof(uint32_t);

	// Allocate memory for the file contents
	uint32_t* contents = (uint32_t*) malloc(sizeof(uint32_t) * num_elems);
	if(contents == NULL)
	{
		fprintf(stderr, "Error: malloc() failed ...\n");
	}
			
	// Read the file contents
	uint32_t elems_read = fread(contents, sizeof(uint32_t), num_elems, uniq_snps);
	if(elems_read != num_elems)
	{
		fprintf(stderr, "Error: elems_read (%d) != num_elems (%d) ...\n", elems_read, num_elems);
	}
			
	// First send the file size
	auto num_elems_buf = new uint32_t[1];
	num_elems_buf[0] = num_elems;
	msgio->send_bin(num_elems_buf, sizeof(uint32_t));

	// Now send the actual file contents
	uint32_t num_elems_rem = num_elems;
	uint32_t num_elems_sent = 0;
	while(num_elems_sent != num_elems)
	{
		uint32_t to_send_elems = 0;
		if(num_elems_rem < chunk_size)
		{	
			to_send_elems = num_elems_rem;
		}
		else
		{
			to_send_elems = chunk_size;
		}
		msgio->send_bin_encrypted(contents + num_elems_sent, to_send_elems * sizeof(uint32_t));
		num_elems_sent = num_elems_sent + to_send_elems;
		num_elems_rem = num_elems_rem - to_send_elems;
	}

	// Close file
	fclose(uniq_snps);

	// Free memory
	free(contents);
	delete[] num_elems_buf;
}

void run_sp(MsgIO* msgio, uint32_t nf, char* fdir, char* ufname, uint32_t csz, int mode)
{
	//int num_files = nf;
	//char* file_dir = fdir;

	// Number of elements to be sent in one round (in 32-bit uint elements, not bytes)
	//uint32_t chunk_size = csz;

	// Directory traversal variables
	DIR* dir;
	struct dirent* ent;

	// 2D array to hold filenames within the directory
	char filenames[nf][MAX_FNAME];

	uint32_t i = 0;
	// Check if the input VCF directory exists
	if((dir = opendir(fdir)) != NULL)
	{
		// Process each entry in the directory
		while((ent = readdir(dir)) != NULL)
		{
			// Ignore current and parent dirs
			if(ent->d_name[0] != '.' && i < nf)
			{			
				// Prepare file path
				strncpy(filenames[i], fdir, strlen(fdir) + 1);
				strncat(filenames[i], "/", strlen("/"));
				strncat(filenames[i], ent->d_name, strlen(ent->d_name));

				// Increment file index
				i++;
			}
		}
		closedir(dir);
	}
	else
	{
		fprintf(stderr, "Error opening input VCF directory\n");
		return 1;
	}

	// Make sure we've processed all files
	assert(i == nf);

	// Randomly shuffle the file names
	int index[nf];
	for(i = 0; i < nf; i++)
	{
		index[i] = i;
	}

	int j;
	for(i = nf - 1; i > 0; i--)
	{
		j = rand() % (i + 1);
		swap(&index[i], &index[j]);
	}
	
	// Currently support 3 distinct protocols
	switch(mode)
	{
		// For hash tables, just send the vcf files in random order
		case 0:
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			break;
		// For sketches, first send the vcf files in random order
		// Then send a single (query) file with the unique SNP IDs
		// Finally send the vcf files again in random order
		case 1:
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			send_encrypted_snpid(msgio, csz, ufname);
			fprintf(stderr, "Completed sending SNP IDs to query.\n");
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			break;
		// For sketches, first send the vcf files in random order
		// Then send a single (query) file with the unique SNP IDs
		// Only return the top l candidates
		case 11:
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			send_encrypted_snpid(msgio, csz, ufname);
			fprintf(stderr, "Completed sending SNP IDs to query.\n");
			break;
		// For popstrat correction and CA chi2 test
		// First send the vcf files in random order two times
		// Then send a single (query) file with the unique SNP IDs
		// Finally send the vcf files again in random order one time
		case 2:
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			send_encrypted_snpid(msgio, csz, ufname);
			fprintf(stderr, "Completed sending SNP IDs to query.\n");
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			break;
		default:
			break;
	}

	return 0;
}

void new_parse(char* param_path, parameters** params, config_t& config)
{
	FILE* param_file;
	char buf[1024];
	char var_name[256];

	// Config stuff
	char flag_spid = 0;
	char flag_pubkey = 0;
	char flag_cert = 0;
	char flag_ca = 0;
	char flag_usage = 0;
	config.sigrl = NULL;
	config.port = NULL;
	config.flag_stdio = 0;
	config.flag_noproxy = 0;
	config.flag_prod = 0;

	// log
	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	// Config defaults
	memset(&config, 0, sizeof(config));
	strncpy((char*) config.cert_type, "PEM", 3);
	config.apiver = IAS_API_DEF_VERSION;

	// Open parameter file
	param_file = fopen(param_path, "r");
	
	while(fgets(buf, 1024, param_file) != NULL)
	{
		if(buf[0] == '#')
		{
			continue;
		}
		buf[strcspn(buf, "\n")] = 0;
	
		int token_cnt = 0;
		char* token = strtok(buf, "=");
		while(token != NULL)
		{
			// First token: variable name
			if(token_cnt == 0)
			{
				strncpy(var_name, token, strlen(token));
				var_name[strlen(token)] = '\0';
				token_cnt = 1;
			}
			// Second token: variable value
			else if(token_cnt == 1)
			{
				if(strcmp(var_name, "PORT_NUMBER") == 0)
				{
					(*params)->port = (char*) malloc(sizeof(char) * (strlen(token) + 1));
					strncpy((*params)->port, token, strlen(token) + 1);

					// config
					config.port = strdup(token);
				}
				else if(strcmp(var_name, "APP_MODE") == 0)
				{
					(*params)->app_mode = (char*) malloc(sizeof(char) * (strlen(token) + 1));
					strncpy((*params)->app_mode, token, strlen(token) + 1);
				}
				else if(strcmp(var_name, "NUM_FILES") == 0)
				{
					(*params)->num_files = atoi(token);
				}
				else if(strcmp(var_name, "VCF_DIR") == 0)
				{
					(*params)->vcf_dir = (char*) malloc(sizeof(char) * (strlen(token) + 1));
					strncpy((*params)->vcf_dir, token, strlen(token) + 1);
				}
				else if(strcmp(var_name, "SNP_IDS") == 0)
				{
					(*params)->snp_ids = (char*) malloc(sizeof(char) * (strlen(token) + 1));
					strncpy((*params)->snp_ids, token, strlen(token) + 1);
				}
				else if(strcmp(var_name, "CHUNK_SIZE") == 0)
				{
					(*params)->chunk_size = atoi(token);
				}
				/*else if(strcmp(var_name, "QUERY_IAS_PRODUCTION") == 0)
				{
					if(atoi(token) == 1)
					{
						config.flag_prod = 1;
					}
				}*/
				else if(strcmp(var_name, "SPID") == 0)
				{
					if(!from_hexstring((unsigned char*) &config.spid, (unsigned char*) token, 16))
					{
						exit(1);
					}
					flag_spid = 1;
				}/*
				else if(strcmp(var_name, "LINKABLE") == 0)
				{
					if(atoi(token) == 1)
					{
						config.quote_type = SGX_LINKABLE_SIGNATURE;
					}
				}*/
				/*
				else if(strcmp(var_name, "RANDOM_NONCE") == 0)
				{
				}
				else if(strcmp(var_name, "USE_PLATFORM_SERVICES") == 0)
				{
				}
				*/
				else if(strcmp(var_name, "IAS_CLIENT_CERT_FILE") == 0)
				{
					config.cert_file = strdup(token);
					if(config.cert_file == NULL)
					{
						exit(1);
					}
					flag_cert = 1;
				}
				else if(strcmp(var_name, "IAS_CLIENT_KEY_FILE") == 0)
				{
					config.cert_key_file = strdup(token);
					if(config.cert_key_file == NULL)
					{
						exit(1);
					}
				}
				else if(strcmp(var_name, "IAS_CLIENT_CERT_TYPE") == 0)
				{
					strncpy((char*) config.cert_type, token, 4);
				}
				else if(strcmp(var_name, "IAS_REPORT_SIGNING_CA_FILE") == 0)
				{
					if(!cert_load_file(&config.signing_ca, token))
					{
						crypto_perror("cert_load_file");
						exit(1);
					}

					config.store = cert_init_ca(config.signing_ca);
					if(config.store == NULL)
					{
						fprintf(stderr, "Could not init certificate store.\n");
						exit(1);
					}
					flag_ca = 1;
				}
				else if(strcmp(var_name, "VERBOSE") == 0)
				{
					// Just for debugging, non critical
				}
				else if(strcmp(var_name, "DEBUG") == 0)
				{
					// Just for debugging, non critical
				}
				else
				{
					fprintf(stderr, "Unknown parameter in configuration file\n");
					fprintf(stderr, "%s\n", var_name);
					exit(1);
				}
				token_cnt = 0;
			}
			token = strtok(NULL, "=");
		}
	}

	fclose(param_file);

	// Use the default CA bundle
	config.ca_bundle = strdup(DEFAULT_CA_BUNDLE);

	// Use hardcoded default key unless one is provided on the cmdline
	config.service_private_key = key_private_from_bytes(def_service_private_key);

	// Final checks before proceeding
	if(!flag_spid)
	{
		fprintf(stderr, "SPID not set.\n");
		exit(1);
	}

	if(!flag_cert)
	{
		fprintf(stderr, "IAS-CERT-FILE is required.\n");
		exit(1);
	}

	if(!flag_ca)
	{
		fprintf(stderr, "IAS-SIGNING-CAFILE is required.\n");
		exit(1);
	}
}

int main(int argc, char** argv)
{
	// Parse the parameters
	config_t config;
	parameters* params;
	init_params(&params);
	new_parse(argv[1], &params, config);
	print_params(params);

	// If necessray parameters are missing, exit.
	if(params->app_mode == NULL || params->vcf_dir == NULL || params->num_files == 0)
	{
		fprintf(stderr, "Missing parameters.\n");
		exit(1);
	}

	MsgIO* msgio;
	//parse(argv[0], NULL, config);
	
	if(!connect(config, &msgio)) 
	{
		remote_attestation(config, msgio);
	
		if(strcmp(params->app_mode, "topk") == 0)
			run_sp(msgio, params->num_files, params->vcf_dir, params->snp_ids, params->chunk_size, 0);
		if(strcmp(params->app_mode, "sketch") == 0)
			run_sp(msgio, params->num_files, params->vcf_dir, params->snp_ids, params->chunk_size, 11);

		//if(strcmp(app_mode, "cms_mt") == 0)
		//	run_sp(msgio);
		//if(strcmp(app_mode, "cms_mt_ca") == 0)
		//	run_sp(msgio);
		//if(strcmp(app_mode, "csk_mt") == 0)
		//	run_sp(msgio);

		if(strcmp(params->app_mode, "sketch_topk") == 0)
			run_sp(msgio, params->num_files, params->vcf_dir, params->snp_ids, params->chunk_size, 1);
		if(strcmp(params->app_mode, "pca_sketch") == 0)
			run_sp(msgio, params->num_files, params->vcf_dir, params->snp_ids, params->chunk_size, 2);
		//if(strcmp(params->app_mode, "sketch_pca_topk") == 0)
		//	run_sp(msgio, params->num_files, params->vcf_dir, params->snp_ids, params->chunk_size, 2);
		
		finalize(msgio, config);
		fprintf(stderr, "Service Provider Closed.\n");
	}
	return 0;
}
