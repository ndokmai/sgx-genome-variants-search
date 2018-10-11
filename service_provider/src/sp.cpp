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
#include "ra.h"
#include "msgio.h"

#define	MAX_FNAME	256

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

void app_test(MsgIO* msgio)
{
	// For sending large data (greater than the enclave buffer can hold at once), we need to break it into chunks
	// The following example app demonstrates this

	// First, determine the total number of elements we are going to send
	uint64_t num_elems = 1000000000;

	// Initialize the data
	auto data = new uint32_t[num_elems];
	for(int i = 0; i < num_elems; i++)
	{
		data[i] = 1;
	}

	// Send the total number of elements we are going to send
	auto num_elems_buf = new uint64_t[1];
	num_elems_buf[0] = num_elems;
	msgio->send_bin(num_elems_buf, sizeof(uint64_t));

	// Number of elements to send in one round (in elements, not bytes)
	uint32_t chunk_size = 16000;

	// Send the data encrypted in chunks
	fprintf(stderr, "Sending data (encrypted) ...\n");
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
		msgio->send_bin_encrypted(data + num_elems_sent, to_send_elems * sizeof(uint32_t));
		num_elems_sent = num_elems_sent + to_send_elems;
		num_elems_rem = num_elems_rem - to_send_elems;
	}

	// Free memory
	delete[] data;
	delete[] num_elems_buf;
}

void app(MsgIO* msgio)
{
	// Number of elements to be sent in one round (in 32-bit uint elements, not bytes)
	uint32_t chunk_size = 500000;

	// Set the file directories
	char* case_dir = "/home/ckockan/test-data/case_ckz0";
	char* control_dir = "/home/ckockan/test-data/control_ckz0";

	// For checking the return values
	size_t elems_read;
	int retval;

	// Structures used to traverse directories
	DIR* dir;
	struct dirent* ent;
	struct stat st;

	// Check if the case VCF directory exists
	fprintf(stderr, "Transferring CASE VCFs ...\n\n");
	if((dir = opendir(case_dir)) != NULL)
	{
		// For each file in the directory
		while((ent = readdir(dir)) != NULL)
		{
			// Ignore current and parent dirs
			if(ent->d_name[0] != '.')
			{
				// Prepare file path
				char filename[MAX_FNAME];
				strncpy(filename, case_dir, strlen(case_dir) + 1);
				strncat(filename, ent->d_name, strlen(ent->d_name));

				// Check if the file is accessible
				if(stat(filename, &st) != -1)
				{
					// Open input binary file for reading
					FILE* file = fopen(filename, "rb");
					if(file == NULL)
					{
						fprintf(stderr, "Error opening file\n");
					}
					fprintf(stderr, "Transferring file: %s\n", filename);

					// Move the file pointer to the end of the file
					fseek(file, 0, SEEK_END);

					// Get the size of the file (in bytes)
					uint32_t file_size = (uint32_t) ftell(file);
					//fprintf(stderr, "Size of file: %d bytes.\n", file_size);

					// Each element in the file should bea 32-bit unsigned integer
					// Therefore we can calculate the total number of elements to be sent for the file
					uint32_t num_elems = file_size / sizeof(uint32_t);

					// Move the file pointer back to the beginning of the file
					rewind(file);

					// Read in file contents
					uint32_t* contents = (uint32_t*) malloc(sizeof(uint32_t) * num_elems);
					if(contents == NULL)
					{
						fprintf(stderr, "Error: malloc() failed ...\n");
					}

					elems_read = fread(contents, sizeof(uint32_t), num_elems, file);
					if(elems_read != num_elems)
					{
						fprintf(stderr, "Error: elems_read (%zu) != num_elems (%d) ...\n", elems_read, num_elems);
					}
					
					// First, send the number of elements to be transferred for the current file
					auto num_elems_buf = new uint32_t[1];
					num_elems_buf[0] = num_elems;
					msgio->send_bin(num_elems_buf, sizeof(uint32_t));

					// Now, send the actual file contents in chunks
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

					// Free memory 
					free(contents);
					delete[] num_elems_buf;
					
					// Close current file
					fclose(file);
				}
			}
		}
		closedir(dir);
	}
	else
	{
		fprintf(stderr, "Error opening CASE VCF directory\n");
	}
	fprintf(stderr, "Transferred CASE VCFs ...\n\n");

	// Repeat for CONTROL VCF files
	fprintf(stderr, "Transferring CONTROL VCFs ...\n\n");
	if((dir = opendir(control_dir)) != NULL)
	{
		// For each file in the directory
		while((ent = readdir(dir)) != NULL)
		{
			// Ignore current and parent dirs
			if(ent->d_name[0] != '.')
			{
				// Prepare file path
				char filename[MAX_FNAME];
				strncpy(filename, control_dir, strlen(control_dir) + 1);
				strncat(filename, ent->d_name, strlen(ent->d_name));

				// Check if the file is accessible
				if(stat(filename, &st) != -1)
				{
					// Open input binary file for reading
					FILE* file = fopen(filename, "rb");
					if(file == NULL)
					{
						fprintf(stderr, "Error opening file\n");
					}
					fprintf(stderr, "Transferring file: %s\n", filename);

					// Move the file pointer to the end of the file
					fseek(file, 0, SEEK_END);

					// Get the size of the file (in bytes)
					uint32_t file_size = (uint32_t) ftell(file);
					//fprintf(stderr, "Size of file: %d bytes.\n", file_size);

					uint32_t num_elems = file_size / sizeof(uint32_t);

					// Move the file pointer back to the beginning of the file
					rewind(file);

					// Read in file contents
					uint32_t* contents = (uint32_t*) malloc(sizeof(uint32_t) * num_elems);
					if(contents == NULL)
					{
						fprintf(stderr, "Error: malloc() failed ...\n");
					}

					elems_read = fread(contents, sizeof(uint32_t), num_elems, file);
					if(elems_read != num_elems)
					{
						fprintf(stderr, "Error: elems_read (%zu) != num_elems (%d) ...\n", elems_read, num_elems);
					}

					// First, send the number of elements to be transferred for the current file
					auto num_elems_buf = new uint32_t[1];
					num_elems_buf[0] = num_elems;
					msgio->send_bin(num_elems_buf, sizeof(uint32_t));

					// Now, send the actual file contents in chunks
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
					
					// Free memory
					free(contents);
					delete[] num_elems_buf;

					// Close file
					fclose(file);
				}
			}
		}
		closedir(dir);
	}
	else
	{
		fprintf(stderr, "Error opening CONTROL VCF directory\n");
	}
	fprintf(stderr, "Transferred CONTROL VCFs ...\n\n");
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
