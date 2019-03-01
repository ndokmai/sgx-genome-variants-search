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
    if(port != NULL) {
        data.push_back(std::string(port) + "\0");
    }

    auto ra_argv = new char*[data.size()];
    for(size_t i=0; i<data.size(); i++) {
        ra_argv[i] = data.at(i).data();
    }
    auto ra_argc = data.size();
    parse_config(ra_argc, ra_argv, config);
    delete[] ra_argv;

    // clean up the args file 
    system("rm _args_");
}

void app(MsgIO* msgio)
{
	// Hardcoded stuff that should be read from a config file really
	int num_files = 2000;
	char* file_dir = "/home/ckockan/test-data/chr1_all_ckz0/";
	//int num_files = 44000;
	//char* file_dir = "/mnt/big_part/ckockan/test-data/all_chr_ckz0/";

	// Number of elements to be sent in one round (in 32-bit uint elements, not bytes)
	uint32_t chunk_size = 500000;

	// Directory traversal variables
	DIR* dir;
	struct dirent* ent;
	struct stat st;

	// 2D array to hold filenames within the directory
	char filenames[num_files][MAX_FNAME];

	int i = 0;
	// Check if the input VCF directory exists
	if((dir = opendir(file_dir)) != NULL)
	{
		// Process each entry in the directory
		while((ent = readdir(dir)) != NULL)
		{
			// Ignore current and parent dirs
			if(ent->d_name[0] != '.' && i < num_files)
			{			
				// Prepare file path
				strncpy(filenames[i], file_dir, strlen(file_dir) + 1);
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
	assert(i == num_files);

	// Randomly shuffle the file names
	int index[num_files];
	for(i = 0; i < num_files; i++)
	{
		index[i] = i;
	}

	int j;
	for(i = num_files - 1; i > 0; i--)
	{
		j = rand() % (i + 1);
		swap(&index[i], &index[j]);
	}
	
	// Now, read and process the files in random order
	for(i = 0; i < num_files; i++)
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
/*
	// Second pass, only send a single file with the unique SNP IDs
	FILE* uniq_snps = fopen("/home/ckockan/data-sgx-misc/chr1_uniq.ckz0", "rb");
	//FILE* uniq_snps = fopen("/home/ckockan/data-sgx-misc/all_uniq.ckz0", "rb");
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
*/

//fprintf(stderr, "\n");
/*
	// Another pass
	// Now, read and process the files in random order
	for(i = 0; i < num_files; i++)
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

	// Last pass, only send a single file with the unique SNP IDs
	FILE* uniq_snps = fopen("/home/ckockan/data-sgx-misc/chr1_uniq.ckz0", "rb");
	//FILE* uniq_snps = fopen("/home/ckockan/data-sgx-misc/all_uniq.ckz0", "rb");
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

	// Another pass
	// Now, read and process the files in random order
	for(i = 0; i < num_files; i++)
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
*/			
	return 0;
}

int main(int argc, char** argv)
{
	config_t config;
	MsgIO* msgio;
	parse(argv[0], argv[1], config);
	if(!connect(config, &msgio)) 
	{
		remote_attestation(config, msgio);
		app(msgio);
		finalize(msgio, config);
	}

	return 0;
}
