#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <thread>
#include "sgx_urts.h"
#include "ra.h"
#include "Enclave_u.h"
#include "msgio.h"

int global_eid;

void run_thread_cms(int thread_num)
{
	sgx_status_t ret;
	ecall_thread_cms(global_eid, &ret, thread_num);
}

void run_thread_cms_ca(int thread_num, int part_num)
{
	sgx_status_t ret;
	ecall_thread_cms_ca(global_eid, &ret, thread_num, part_num);
}

void run_thread_csk(int thread_num)
{
	sgx_status_t ret;
	ecall_thread_csk(global_eid, &ret, thread_num);
}

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

void app_rhht(MsgIO* msgio, config_t& config)
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
	uint32_t num_files = num_case_files + num_control_files;

	size_t i;
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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
			enclave_decrypt_process_rhht(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Make an ECALL to perform the chi-squared test
	rhht_init_chi_sq(eid, case_count, control_count);

	// Make an ECALL to receive the result
	/*
	uint32_t my_res[10];
	enclave_get_res_buf(eid, my_res);
	for(int i = 0; i < 10; i++)
	{
		fprintf(stderr, "%lu\n", (unsigned long) my_res[i]);
	}
	*/

	// Stop timer
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;

	// Report results
	fprintf(stderr, "time: %lf\n", duration);
}

void app_oa(MsgIO* msgio, config_t& config)
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
	enclave_init_oa(eid);

	// Set the chunk size for receiving large data
	uint32_t chunk_size = 1000000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	uint32_t num_case_files = case_count / 2;
	uint32_t num_control_files = control_count / 2;
	uint32_t num_files = num_case_files + num_control_files;

	size_t i;
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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
			enclave_decrypt_process_oa(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Make an ECALL to perform the chi-squared test
	oa_init_chi_sq(eid, case_count, control_count);

	// Make an ECALL to receive the result
	/*
	uint32_t my_res[10];
	enclave_get_res_buf(eid, my_res);
	for(int i = 0; i < 10; i++)
	{
		fprintf(stderr, "%lu\n", (unsigned long) my_res[i]);
	}
	*/

	// Stop timer
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;

	// Report results
	fprintf(stderr, "time: %lf\n", duration);
}

void app_cmtf(MsgIO* msgio, config_t& config)
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
	enclave_init_cmtf(eid);

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
			enclave_decrypt_process_cmtf(eid, ra_ctx, ciphertext, ciphertext_len, 1);
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
			enclave_decrypt_process_cmtf(eid, ra_ctx, ciphertext, ciphertext_len, 0);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;

			//chunk_num = chunk_num + 1;
		}
	}

	// Make an ECALL to perform the chi-squared test
	cmtf_init_chi_sq(eid, case_count, control_count);

	// Make an ECALL to receive the result
	/*
	uint32_t my_res[10];
	enclave_get_res_buf(eid, my_res);
	for(int i = 0; i < 10; i++)
	{
		fprintf(stderr, "%lu\n", (unsigned long) my_res[i]);
	}
	//uint64_t result = 0;
	//enclave_get_result_rhht(eid, &result);
	*/

	// Stop timer
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;

	// Report results
	//fprintf(stderr, "result: %lu\n", (unsigned long) result);
	fprintf(stderr, "time: %lf\n", duration);
}

void app_csk(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CSK structure
	enclave_init_csk(eid);

	// Set the chunk size for receiving large amounts of data
	uint32_t chunk_size = 500000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	//uint32_t num_files = 2000;
	uint32_t num_files = 44000;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CSK structure
	size_t i;
	fprintf(stderr, "First Pass, updating CSK ...\n");
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "First pass, processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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
			enclave_decrypt_update_csk(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CSK) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CSK structure
	fprintf(stderr, "Second pass, querying CSK ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin(&num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
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
		enclave_decrypt_query_csk(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Second Pass (CSK) took: %lf seconds\n", duration);

	// Make a final ECALL to receive the results and report results
	/*
	uint32_t* my_res;
	my_res = (uint32_t*) malloc(sizeof(uint32_t) * (1 << 17));

	enclave_get_res(eid, my_res);

	for(size_t i = 0; i < (1 << 17); i++)
	{
		fprintf(stdout, "rs%lu\n", (unsigned long) my_res[i]);
	}
	free(my_res);
	*/
}

void app_cms(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CMS structure
	enclave_init_cms(eid);

	// Set the chunk size for receiving large amounts of data
	uint32_t chunk_size = 500000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	//uint32_t num_files = 2000;
	uint32_t num_files = 44000;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CMS structure
	size_t i;
	fprintf(stderr, "First Pass, updating CMS ...\n");
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "First Pass, processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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
			enclave_decrypt_update_cms(eid, ra_ctx, ciphertext, ciphertext_len);
			
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CMS) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CMS structure
	fprintf(stderr, "Second pass, querying CMS ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin(&num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
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
		enclave_decrypt_query_cms(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Stop timer and report time for the second pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Second Pass (CMS) took: %lf seconds\n", duration);

	// Make a final ECALL to receive the results and report results
	/*
	uint32_t* my_res;
	my_res = (uint32_t*) malloc(sizeof(uint32_t) * (1 << 17));

	enclave_get_res(eid, my_res);

	for(size_t i = 0; i < (1 << 17); i++)
	{
		fprintf(stdout, "rs%lu\n", (unsigned long) my_res[i]);
	}
	free(my_res);
	*/
}

void app_cms_mt(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;
	global_eid = eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CMS structure
	enclave_init_cms(eid);

	// Set the chunk size for receiving large amounts of data
	uint32_t chunk_size = 500000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	uint32_t num_files = 2000;
	//uint32_t num_files = 44000;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CMS structure
	size_t i;
	fprintf(stderr, "First Pass, updating CMS ...\n");
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "First Pass, processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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

			enclave_decrypt_store_cms(eid, ra_ctx, ciphertext, ciphertext_len);

			std::thread t0(run_thread_cms, 0);
			std::thread t1(run_thread_cms, 1);
			std::thread t2(run_thread_cms, 2);
			std::thread t3(run_thread_cms, 3);
			std::thread t4(run_thread_cms, 4);
			std::thread t5(run_thread_cms, 5);
			std::thread t6(run_thread_cms, 6);
			std::thread t7(run_thread_cms, 7);

			t0.join();
			t1.join();
			t2.join();
			t3.join();
			t4.join();
			t5.join();
			t6.join();
			t7.join();

			enclave_clear_cms(eid, ra_ctx);

			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CMS) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CMS structure
	fprintf(stderr, "Second pass, querying CMS ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin(&num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
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
		enclave_decrypt_query_cms(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Stop timer and report time for the second pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Second Pass (CMS) took: %lf seconds\n", duration);

	// Make a final ECALL to receive the results and report results
	/*
	uint32_t* my_res;
	my_res = (uint32_t*) malloc(sizeof(uint32_t) * (1 << 17));

	enclave_get_res(eid, my_res);

	for(size_t i = 0; i < (1 << 17); i++)
	{
		fprintf(stdout, "rs%lu\n", (unsigned long) my_res[i]);
	}
	free(my_res);
	*/
}

void app_cms_mt_ca(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;
	global_eid = eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CMS structure
	enclave_init_cms(eid);

	// Set the chunk size for receiving large amounts of data
	uint32_t chunk_size = 500000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	//uint32_t num_files = 2000;
	uint32_t num_files = 44000;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CMS structure
	size_t i;
	size_t j;
	fprintf(stderr, "First Pass, updating CMS ...\n");
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "First Pass, processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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

			// Decrypt and store data
			enclave_decrypt_store_cms(eid, ra_ctx, ciphertext, ciphertext_len);

			// Cache aware CMS update, 4-pass, multithreader
			for(j = 0; j < 8; j = j + 2)
			{
				std::thread t0(run_thread_cms, j);
				std::thread t1(run_thread_cms, j + 1);
				//std::thread t0(run_thread_cms_ca, j, 0);
				//std::thread t1(run_thread_cms_ca, j, 1);
				//std::thread t2(run_thread_cms_ca, j + 1, 0);
				//std::thread t3(run_thread_cms_ca, j + 1, 1);

				t0.join();
				t1.join();
				//t2.join();
				//t3.join();
			}

			// Free the plaintext buffer inside the enclave
			enclave_clear_cms(eid, ra_ctx);

			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CMS) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CMS structure
	fprintf(stderr, "Second pass, querying CMS ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin(&num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
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
		enclave_decrypt_query_cms(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Stop timer and report time for the second pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Second Pass (CMS) took: %lf seconds\n", duration);
}

void app_csk_mt(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;
	global_eid = eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CMS structure
	enclave_init_csk(eid);

	// Set the chunk size for receiving large amounts of data
	uint32_t chunk_size = 500000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	//uint32_t num_files = 2000;
	uint32_t num_files = 44000;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CSK structure
	size_t i;
	fprintf(stderr, "First Pass, updating CSK ...\n");
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "First Pass, processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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

			enclave_decrypt_store_csk(eid, ra_ctx, ciphertext, ciphertext_len);

			std::thread t0(run_thread_csk, 0);
			std::thread t1(run_thread_csk, 1);
			std::thread t2(run_thread_csk, 2);
			std::thread t3(run_thread_csk, 3);
			std::thread t4(run_thread_csk, 4);
			std::thread t5(run_thread_csk, 5);
			std::thread t6(run_thread_csk, 6);
			std::thread t7(run_thread_csk, 7);

			t0.join();
			t1.join();
			t2.join();
			t3.join();
			t4.join();
			t5.join();
			t6.join();
			t7.join();

			enclave_clear_csk(eid, ra_ctx);

			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CSK) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CSK structure
	fprintf(stderr, "Second pass, querying CSK ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin(&num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
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
		enclave_decrypt_query_csk(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Stop timer and report time for the second pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Second Pass (CSK) took: %lf seconds\n", duration);

	// Make a final ECALL to receive the results and report results
	/*
	uint32_t* my_res;
	my_res = (uint32_t*) malloc(sizeof(uint32_t) * (1 << 17));

	enclave_get_res(eid, my_res);

	for(size_t i = 0; i < (1 << 17); i++)
	{
		fprintf(stdout, "rs%lu\n", (unsigned long) my_res[i]);
	}
	free(my_res);
	*/
}

void app_sketch_rhht(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CMS structure
	enclave_init_cms(eid);

	// Set the chunk size for receiving large amounts of data
	uint32_t chunk_size = 500000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	uint32_t num_files = 2000;
	//uint32_t num_files = 44000;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CMS structure
	size_t i;
	fprintf(stderr, "First Pass, updating CMS ...\n");
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "First Pass, processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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
			enclave_decrypt_update_cms(eid, ra_ctx, ciphertext, ciphertext_len);
			
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CMS) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CMS structure
	fprintf(stderr, "Second pass, querying CMS ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin(&num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
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
		enclave_decrypt_query_cms(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Stop timer and report time for the second pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Second Pass (CMS) took: %lf seconds\n", duration);
	
	// Restart timer
	start = std::clock();

	// Third Pass: Use rhht and mh to report actual chi-sqaured/p-values for the top-k SNPs
	fprintf(stderr, "Third pass, querying MH ...\n");
	enclave_init_sketch_rhht(eid);

	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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
			enclave_decrypt_process_sketch_rhht(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the third pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Third Pass (RHHT/MH) took: %lf seconds\n", duration);

	// Make an ECALL to perform the chi-squared test
	rhht_init_chi_sq(eid, case_count, control_count);

	// Make an ECALL to receive the result
	uint32_t my_res[1000];
	enclave_get_res_buf(eid, my_res);
	for(int i = 0; i < 1000; i++)
	{
		fprintf(stderr, "%lu\n", (unsigned long) my_res[i]);
	}
}

void app_svd_mcsk(MsgIO* msgio, config_t& config)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CSK structure
	enclave_init_mcsk(eid);

	// Set the chunk size for receiving large amounts of data
	uint32_t chunk_size = 500000;

	// Set app specific variables
	uint32_t case_count = 2000;
	uint32_t control_count = 2000;
	uint32_t num_files = 2000;
	//uint32_t num_files = 44000;

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the MCSK structure
	size_t i;
	fprintf(stderr, "First Pass, updating MCSK ...\n");
	for(i = 0; i < num_files; i++)
	{
		//fprintf(stderr, "First pass, processing file: %d ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin(&num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
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
			enclave_decrypt_update_mcsk(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (MCSK) took: %lf seconds\n", duration);

	// Perform mean centering before SVD
	enclave_mcsk_mean_centering(eid);

	// DEBUG
	mcsk_pull_row(eid);
	float my_res[2001];
	enclave_get_mcsk_res(eid, my_res);
	for(int i = 0; i < 2001; i++)
	{
		fprintf(stderr, "%f\n", my_res[i]);
	}

	// SVD
	enclave_svd(eid);
}

int main(int argc, char** argv)
{
	config_t config;
	MsgIO* msgio;
	parse(argv[0], argv[1], config);
	if(!remote_attestation(config, &msgio))
	{
		//app_oa(msgio,config);
		//app_rhht(msgio, config);
		//app_cmtf(msgio, config);
		//app_cms(msgio, config);
		//app_csk(msgio, config);
		//app_cms_mt(msgio, config);
		//app_cms_mt_ca(msgio, config);
		//app_csk_mt(msgio, config);
		//app_sketch_rhht(msgio, config);
		app_svd_mcsk(msgio, config);
		finalize(msgio, config);
	}
}
