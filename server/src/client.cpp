#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include "ra.h"
#include "Enclave_u.h"
#include "msgio.h"

int parse(char* process_name, char* host_port, config_t &config)
{
    // call the script to generate args file
    system("./get_args_from_settings.sh");

    // parse args file
    std::vector<std::string> data{};

    data.push_back(std::string(process_name)+="\0");

    // add host[:port]
    if(host_port!=NULL) {
        data.push_back(std::string(host_port)+="\0");
    }
    
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

void app_test(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Start timer
	std::clock_t start;
	double duration;
	fprintf(stderr, "Start timer ...\n");
	start = std::clock();

	// Make an ECALL to initialize the Enclave data structures
	enclave_init_sum(eid);

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin(&num_elems_buf, &len_num_elems);
	uint64_t num_elems = ((uint64_t*) num_elems_buf)[0];
	fprintf(stderr, "num_elems: %llu\n", (unsigned long long) num_elems);

	// Set the chunk size for receiving large data
	uint32_t chunk_size = 16000;

	// Now, receive and process next data chunk until all data is processed
	fprintf(stderr, "Receiving data (encrypted) ...\n");
	uint32_t num_elems_rem = num_elems;
	uint32_t num_elems_rcvd = 0;
	while(num_elems_rcvd != num_elems)
	{
		size_t to_read_elems = 0;
		if(num_elems_rem < chunk_size)
		{
			to_read_elems = num_elems_rem;
		}
		else
		{
			to_read_elems = chunk_size;
		}
		
		// Receive data (encrypted)
		uint8_t* ciphertext;
		size_t ciphertext_len;
		msgio->read_bin(&ciphertext, &ciphertext_len);

		// Make an ECALL to decrypt the data and process it inside the Enclave
		enclave_decrypt_process(eid, ra_ctx, ciphertext, ciphertext_len);

		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Make an ECALL to receive the result
	uint64_t result = 0;
	enclave_get_result(eid, &result);

	// Stop timer
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Finish timer\n");

	// Report results
	fprintf(stderr, "result: %lu\n", (unsigned long) result);
	fprintf(stderr, "time: %lf\n", duration);
}

void app(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// Make an ECALL to initialize the Enclave data structures
	enclave_init_rhht(eid);

	// Set the chunk size for receiving large data
	uint32_t chunk_size = 1000000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	uint32_t num_case_files = case_count / 2;
	uint32_t num_control_files = control_count / 2;
	size_t i;

	for(i = 0; i < num_case_files; i++)
	{
		fprintf(stderr, "Processing case file: %d ...\n", i);
		//uint32_t chunk_num = 0;

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];
		//fprintf(stderr, "num_elems: %llu\n", (unsigned long long) num_elems);

		// Now, receive and process next data chunk until all data is processed
		//fprintf(stderr, "Receiving data (encrypted) ...\n");
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < chunk_size)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = chunk_size;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin(&ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			//enclave_decrypt_process_rhht(eid, ra_ctx, ciphertext, ciphertext_len, 1, chunk_num);
			enclave_decrypt_process_rhht(eid, ra_ctx, ciphertext, ciphertext_len, 1);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;

			//chunk_num = chunk_num + 1;
		}
	}

	for(i = 0; i < num_control_files; i++)
	{
		fprintf(stderr, "Processing control file: %d ...\n", i);
		//uint32_t chunk_num = 0;

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];
		//fprintf(stderr, "num_elems: %llu\n", (unsigned long long) num_elems);

		// Now, receive and process next data chunk until all data is processed
		//fprintf(stderr, "Receiving data (encrypted) ...\n");
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < chunk_size)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = chunk_size;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin(&ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			//enclave_decrypt_process_rhht(eid, ra_ctx, ciphertext, ciphertext_len, 0, chunk_num);
			enclave_decrypt_process_rhht(eid, ra_ctx, ciphertext, ciphertext_len, 0);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;

			//chunk_num = chunk_num + 1;
		}
	}

	// Make an ECALL to perform the chi-squared test
	// Make an ECALL to receive the result
	//uint64_t result = 0;
	//enclave_get_result_rhht(eid, &result);

	// Stop timer
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;

	// Report results
	//fprintf(stderr, "result: %lu\n", (unsigned long) result);
	fprintf(stderr, "time: %lf\n", duration);
}

int main(int argc, char** argv)
{
	config_t config;
	MsgIO* msgio;
	parse(argv[0], argv[1], config);
	if(!remote_attestation(config, &msgio))
	{
		app(msgio, config);
		finalize(msgio, config);
	}
}
