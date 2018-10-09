#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string.h>
#include "ra.h"
#include "msgio.h"

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
	// For sending large data (greater than the enclave buffer can hold at once), we need to break it into chunks
	// The following example app demonstrates this

	// First, determine the total number of elements we are going to send
	uint64_t num_elems = 2 * 100000 * 10000;

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
	uint32_t chunk_size = 128000;

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
