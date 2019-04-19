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

#define	MAX_FNAME	96

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

void send_encrypted_vcf(MsgIO* msgio, int num_files, int chunk_size, int index[], char filenames[][MAX_FNAME])
{
	struct stat st;

	for(int i = 0; i < num_files; i++)
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

void run_sp(MsgIO* msgio, int nf, char* fdir, char* ufname, uint32_t csz, int mode)
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

	int i = 0;
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
			fprintf(stderr, "Completed sending SNP IDs to query.");
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
			fprintf(stderr, "Completed sending SNP IDs to query.");
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
			fprintf(stderr, "Completed sending SNP IDs to query.");
			send_encrypted_vcf(msgio, nf, csz, index, filenames);
			fprintf(stderr, "Completed sending vcf files in random order.\n");
			break;
		default:
			break;
	}

	return 0;
}

int main(int argc, char** argv)
{
	int opt;
	int opt_index;

	// IN PROGRESS: Default Parameters
	char* host_port = NULL;
	char* app_mode = NULL;
	char* vcf_dir = NULL;
	char* snpid_file = NULL;
	int num_files = -1;

	static struct option long_options[] =
	{
		{"PORT_NUMBER", optional_argument, 0, 'p'},
		{"APP_MODE", required_argument, 0, 'm'},
		{"NUM_FILES", required_argument, 0, 'n'},
		{"VCF_DIR", required_argument, 0, 'd'},
		{"SNP_IDS", optional_argument, 0, 'q'},
	};

	while(-1 != (opt = getopt_long(argc, argv, "hp:m:n:d:q:", long_options, &opt_index)))
	{
		switch(opt)
		{
			case 'h':
				//print_help();
				return 0;
			case 'p':
				host_port = strdup(optarg); // NOTE: strdup does malloc
				break;
			case 'd':
				vcf_dir = strdup(optarg); // NOTE: strdup does malloc
				break;
			case 'q':
				snpid_file = strdup(optarg); // NOTE: strdup does malloc
				break;
			case 'm':
				app_mode = strdup(optarg); // NOTE: strdup does malloc
				break;
			case 'n':
				num_files = stoi(optarg);
				break;
			default:
				//print_help();
				return 0;
		}
	}

	if(app_mode == NULL || vcf_dir == NULL || num_files == -1)
	{
		return 0;
	}

	optind = 1;
	config_t config;
	MsgIO* msgio;

	// DEBUG
	//std::cout << app_mode << "\t" << vcf_dir << std::endl;
	//std::cout << "HERE-1" << std::endl;
	parse(argv[0], host_port, config);
	//std::cout << "HERE-2" << std::endl;

	// Compressed and encrypted VCF files chr1: "/home/ckockan/test-data/chr1_all_ckz0/"
	// Compressed and encrypted VCF files all chrs: "/mnt/big_part/ckockan/test-data/all_chr_ckz0/"
	// Unique SNP IDs on chr1: "/home/ckockan/data-sgx-misc/chr1_uniq.ckz0"
	// Unique SNP IDs all chrs: "/home/ckockan/data-sgx-misc/all_uniq.ckz0"
	if(!connect(config, &msgio)) 
	{
		remote_attestation(config, msgio);
		
		if(strcmp(app_mode, "oa") == 0)
			run_sp(msgio, num_files, vcf_dir, snpid_file, 500000, 0);
		if(strcmp(app_mode, "rhht") == 0)
			run_sp(msgio, num_files, vcf_dir, snpid_file, 500000, 0);
		if(strcmp(app_mode, "cmtf") == 0)
			run_sp(msgio, num_files, vcf_dir, snpid_file, 500000, 0);
		if(strcmp(app_mode, "cms") == 0)
			run_sp(msgio, num_files, vcf_dir, snpid_file, 500000, 11);
		if(strcmp(app_mode, "csk") == 0)
			run_sp(msgio, num_files, vcf_dir, snpid_file, 500000, 11);
		//if(strcmp(app_mode, "cms_mt") == 0)
		//	run_sp(msgio);
		//if(strcmp(app_mode, "cms_mt_ca") == 0)
		//	run_sp(msgio);
		//if(strcmp(app_mode, "csk_mt") == 0)
		//	run_sp(msgio);
		if(strcmp(app_mode, "sketch_rhht") == 0)
			run_sp(msgio, num_files, vcf_dir, snpid_file, 500000, 1);
		if(strcmp(app_mode, "svd_mcsk") == 0)
			run_sp(msgio, num_files, vcf_dir, snpid_file, 500000, 2);
		
		//char* file_dir = ;
		//FILE* uniq_snps = fopen(, "rb");
		//"/home/ckockan/test-data/chr1_all_ckz0/"
		//csz = 500000
		finalize(msgio, config);
		
		fprintf(stderr, "Completed SP.\n");
	}

	return 0;
}
