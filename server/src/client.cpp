#include <errno.h>
#include <getopt.h>
#include <string.h>
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
#include "app_params.h"
#include "logfile.h"
#include "hexutil.h"
#include "common.h"
#include "crypto.h"
#include "config.h"
#include "sgx_detect.h"
#include "../Enclave/util.h"
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

# define ENCLAVE_NAME "Enclave.signed.so"

# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

int global_eid;

int cmpfunc_pair(const void *a, const void *b)
{
	res_pair pa = *(const res_pair*) a;
	res_pair pb = *(const res_pair*) b;
	
	int d = (pa.value > pb.value) - (pa.value < pb.value);
	if(d == 0)
		return (pa.key - pb.key);
	return d;
}

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

/*int parse(char* process_name, char* host_port, config_t &config)
{
	int retval;

    // call the script to generate args file
    retval = system("./get_args_from_settings.sh");

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
        ra_argv[i] = (char *)data.at(i).data();
    }
    auto ra_argc = data.size();
    parse_config(ra_argc, ra_argv, config);
    delete[] ra_argv;

    // clean up the args file 
	retval = system("rm _args_");
}*/

void app_rhht(MsgIO* msgio, config_t& config, uint32_t nf, uint32_t nf_case, uint32_t csz, int k, char *ofn)
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

	// Set app specific variables
	uint32_t num_files = nf;
	uint32_t num_case_files = nf_case;
	uint32_t num_control_files = nf - nf_case;
	uint32_t case_count = (num_case_files << 1);
	uint32_t control_count = (num_control_files << 1);

	size_t i;
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Processing file: %lu ...\n", (unsigned long) i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < csz)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = csz;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			enclave_decrypt_process_rhht(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Make an ECALL to perform the chi-squared test
	enclave_init_id_buf(eid, k);
	enclave_init_res_buf(eid, k);
	rhht_init_chi_sq(eid, case_count, control_count, k);

	// Make an ECALL to receive the result
	res_pair *chi_sq_pairs;
	chi_sq_pairs = (res_pair*) malloc(k * sizeof(res_pair));
	enclave_get_res_pairs(eid, chi_sq_pairs, k);
	qsort(chi_sq_pairs, k, sizeof(res_pair), cmpfunc_pair);

	FILE* file = fopen(ofn, "w");
	if(file == NULL)
	{
		perror("Error opening file: ");
	}
	fprintf(file, "SNP_ID\tCHI_SQ_VAL\n");
	for(int i = 0; i < k; i++)
	{
		fprintf(file, "%u\t%.4f\n", chi_sq_pairs[i].key, chi_sq_pairs[i].value);
	}
	fclose(file);

	// Stop timer
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
	// Report results
	fprintf(stderr, "time: %lf\n", duration);

	free(chi_sq_pairs);
	enclave_free_id_buf(eid);
	enclave_free_res_buf(eid);
}

void app_oa(MsgIO* msgio, config_t& config, uint32_t nf, uint32_t nf_case, uint32_t csz, int k, char *ofn)
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

	// Set app specific variables
	uint32_t num_files = nf;
	uint32_t num_case_files = nf_case;
	uint32_t num_control_files = nf - nf_case;
	uint32_t case_count = (num_case_files << 1);
	uint32_t control_count = (num_control_files << 1);

	size_t i;
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Processing file: %lu ...\n", (unsigned long) i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < csz)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = csz;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			enclave_decrypt_process_oa(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Make an ECALL to perform the chi-squared test
	enclave_init_id_buf(eid, k);
	enclave_init_res_buf(eid, k);
	oa_init_chi_sq(eid, case_count, control_count, k);

	// Make an ECALL to receive the result
	res_pair *chi_sq_pairs;
	chi_sq_pairs = (res_pair*) malloc(k * sizeof(res_pair));
	enclave_get_res_pairs(eid, chi_sq_pairs, k);
	qsort(chi_sq_pairs, k, sizeof(res_pair), cmpfunc_pair);

	FILE* file = fopen(ofn, "w");
	if(file == NULL)
	{
		perror("Error opening file: ");
	}
	fprintf(file, "SNP_ID\tCHI_SQ_VAL\n");
	for(int i = 0; i < k; i++)
	{
		fprintf(file, "%u\t%.4f\n", chi_sq_pairs[i].key, chi_sq_pairs[i].value);
	}
	fclose(file);

	// Stop timer
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;

	// Report results
	fprintf(stderr, "time: %lf\n", duration);
	free(chi_sq_pairs);
	enclave_free_id_buf(eid);
	enclave_free_res_buf(eid);
}

void app_cmtf(MsgIO* msgio, config_t& config, uint32_t nf, uint32_t nf_case, uint32_t csz, int k, char *ofn)
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

	// Set app specific variables
	uint32_t num_files = nf;
	uint32_t num_case_files = nf_case;
	uint32_t num_control_files = nf - nf_case;
	uint32_t case_count = (num_case_files << 1);
	uint32_t control_count = (num_control_files << 1);

	size_t i;
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Processing file: %lu ...\n", (unsigned long) i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < csz)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = csz;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			enclave_decrypt_process_cmtf(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Make an ECALL to perform the chi-squared test
	enclave_init_id_buf(eid, k);
	enclave_init_res_buf(eid, k);
	cmtf_init_chi_sq(eid, case_count, control_count, k);

	// Make an ECALL to receive the result
	res_pair *chi_sq_pairs;
	chi_sq_pairs = (res_pair*) malloc(k * sizeof(res_pair));
	enclave_get_res_pairs(eid, chi_sq_pairs, k);
	qsort(chi_sq_pairs, k, sizeof(res_pair), cmpfunc_pair);

	FILE* file = fopen(ofn, "w");
	if(file == NULL)
	{
		perror("Error opening file: ");
	}
	fprintf(file, "SNP_ID\tCHI_SQ_VAL\n");
	for(int i = 0; i < k; i++)
	{
		fprintf(file, "%u\t%.4f\n", chi_sq_pairs[i].key, chi_sq_pairs[i].value);
	}
	fclose(file);

	// Stop timer
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;

	// Report results
	//fprintf(stderr, "result: %lu\n", (unsigned long) result);
	fprintf(stderr, "time: %lf\n", duration);
	free(chi_sq_pairs);
	enclave_free_id_buf(eid);
	enclave_free_res_buf(eid);
}

void app_csk(MsgIO* msgio, config_t& config, uint32_t nf, uint32_t nf_case, uint32_t csz, int l, char *ofn, \
	int k, int w, int d, int rup)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CSK structure
	enclave_init_csk(eid, w, d);

	// Set app specific variables
	uint32_t num_files = nf;
	uint32_t num_case_files = nf_case;
	uint32_t num_control_files = nf - nf_case;
	uint32_t case_count = (num_case_files << 1);
	uint32_t control_count = (num_control_files << 1);

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CSK structure
	size_t i;
	fprintf(stderr, "First Pass, updating CSK ...\n");
	
	// Row update is disabled
	if(rup == 0)
	{
		for(i = 0; i < num_files; i++)
		{
			fprintf(stderr, "First pass, processing file: %lu ...\n", (unsigned long) i);

			// First, receive the total number of elements to be received
			uint8_t* num_elems_buf;
			size_t len_num_elems;
			msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
			uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

			// Now, receive and process next data chunk until all data is processed
			uint32_t num_elems_rem = num_elems;
			uint32_t num_elems_rcvd = 0;
			while(num_elems_rcvd != num_elems)
			{
				size_t to_read_elems = 0;
				if(num_elems_rem < csz)
				{
					to_read_elems = num_elems_rem;
				}
				else
				{
					to_read_elems = csz;
				}
		
				// Receive data (encrypted)
				uint8_t* ciphertext;
				size_t ciphertext_len;
				msgio->read_bin((void**) &ciphertext, &ciphertext_len);

				// Make an ECALL to decrypt the data and process it inside the Enclave
				enclave_decrypt_update_csk(eid, ra_ctx, ciphertext, ciphertext_len);
				num_elems_rcvd = num_elems_rcvd +  to_read_elems;
				num_elems_rem = num_elems_rem - to_read_elems;

				// We've processed the secret data, now either clean it up or use data sealing for a second pass later
				delete[] ciphertext;
			}
		}
	}
	// Row update is enabled
	else
	{
		for(i = 0; i < num_files; i++)
		{
			fprintf(stderr, "First pass, processing file: %lu ...\n", (unsigned long) i);

			// First, receive the total number of elements to be received
			uint8_t* num_elems_buf;
			size_t len_num_elems;
			msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
			uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

			// Now, receive and process next data chunk until all data is processed
			uint32_t num_elems_rem = num_elems;
			uint32_t num_elems_rcvd = 0;
			while(num_elems_rcvd != num_elems)
			{
				size_t to_read_elems = 0;
				if(num_elems_rem < csz)
				{
					to_read_elems = num_elems_rem;
				}
				else
				{
					to_read_elems = csz;
				}
		
				// Receive data (encrypted)
				uint8_t* ciphertext;
				size_t ciphertext_len;
				msgio->read_bin((void**) &ciphertext, &ciphertext_len);

				// Make an ECALL to decrypt the data and process it inside the Enclave
				enclave_decrypt_update_csk_row(eid, ra_ctx, ciphertext, ciphertext_len);
				num_elems_rcvd = num_elems_rcvd +  to_read_elems;
				num_elems_rem = num_elems_rem - to_read_elems;

				// We've processed the secret data, now either clean it up or use data sealing for a second pass later
				delete[] ciphertext;
			}
		}
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CSK) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid, l);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CSK structure
	fprintf(stderr, "Second pass, querying CSK ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
	uint32_t num_elems_rem = num_elems;
	uint32_t num_elems_rcvd = 0;
	while(num_elems_rcvd != num_elems)
	{
		size_t to_read_elems = 0;
		if(num_elems_rem < csz)
		{
			to_read_elems = num_elems_rem;
		}
		else
		{
			to_read_elems = csz;
		}
		
		// Receive data (encrypted)
		uint8_t* ciphertext;
		size_t ciphertext_len;
		msgio->read_bin((void**) &ciphertext, &ciphertext_len);

		// Make an ECALL to decrypt the data and process it inside the Enclave
		enclave_decrypt_query_csk(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Make a final ECALL to receive the results and report results
	if(k <= 0)
	{ 
		uint32_t top_ids[l];
		uint16_t acdiff_vals[l];
		enclave_get_mh_ids(eid, top_ids, l);
		enclave_get_mh_vals(eid, acdiff_vals, l);
		FILE* file = fopen(ofn, "w");
		fprintf(file, "SNP_ID\tALLELE_CNT_DIFF_VAL\n");
		for(int i = 0; i < l; i++)
		{
			fprintf(file, "%u\t%u\n", top_ids[i], acdiff_vals[i]);
		}
		fclose(file);
		duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
		fprintf(stderr, "Second Pass (CSK) took: %lf seconds\n", duration);
	}
	else
	{
		duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
		fprintf(stderr, "Second Pass (CSK) took: %lf seconds\n", duration);

		start = std::clock();
		fprintf(stderr, "Third pass, querying MH ...\n");
		enclave_init_sketch_rhht(eid, l);
		for(i = 0; i < num_files; i++)
		{
			fprintf(stderr, "Processing file: %lu ...\n", (unsigned long) i);

			// First, receive the total number of elements to be received
			uint8_t* num_elems_buf;
			size_t len_num_elems;
			msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
			uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

			// Now, receive and process next data chunk until all data is processed
			uint32_t num_elems_rem = num_elems;
			uint32_t num_elems_rcvd = 0;
			while(num_elems_rcvd != num_elems)
			{
				size_t to_read_elems = 0;
				if(num_elems_rem < csz)
				{
					to_read_elems = num_elems_rem;
				}
				else
				{
					to_read_elems = csz;
				}
		
				// Receive data (encrypted)
				uint8_t* ciphertext;
				size_t ciphertext_len;
				msgio->read_bin((void**) &ciphertext, &ciphertext_len);

				// Make an ECALL to decrypt the data and process it inside the Enclave
				enclave_decrypt_process_sketch_rhht(eid, ra_ctx, ciphertext, ciphertext_len);
				num_elems_rcvd = num_elems_rcvd +  to_read_elems;
				num_elems_rem = num_elems_rem - to_read_elems;

				// We've processed the secret data, now either clean it up or use data sealing for a second pass later
				delete[] ciphertext;
			}
		}

		// Make an ECALL to perform the chi-squared test
		rhht_init_chi_sq(eid, case_count, control_count, k);

		// Make an ECALL to receive the result
		uint32_t top_ids[k];
		float chi_sq_vals[k];
		enclave_get_id_buf(eid, top_ids, k);
		enclave_get_res_buf(eid, chi_sq_vals, k);
		FILE* file = fopen(ofn, "w");
		fprintf(file, "SNP_ID\tCHI_SQ_VAL\n");
		for(int i = 0; i < k; i++)
		{
			fprintf(file, "%u\t%.4f\n", top_ids[i], chi_sq_vals[i]);
		}
		fclose(file);

		// Stop timer and report time for the third pass over the data
		duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
		fprintf(stderr, "Third Pass (RHHT/MH) took: %lf seconds\n", duration);
	}
}

void app_cms(MsgIO* msgio, config_t& config, uint32_t nf, uint32_t nf_case, uint32_t csz, int l, char *ofn, \
	int k, int w, int d, int rup)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CMS structure
	enclave_init_cms(eid, w, d);

	// Set app specific variables
	uint32_t num_files = nf;
        uint32_t num_case_files = nf_case;
        uint32_t num_control_files = nf - nf_case;
        uint32_t case_count = (num_case_files << 1);
        uint32_t control_count = (num_control_files << 1);

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the CMS structure
	size_t i;
	fprintf(stderr, "First Pass, updating CMS ...\n");

	 // Row update is disabled
        if(rup == 0)
        {
		for(i = 0; i < num_files; i++)
		{
			fprintf(stderr, "First Pass, processing file: %lu ...\n", (unsigned long) i);

			// First, receive the total number of elements to be received
			uint8_t* num_elems_buf;
			size_t len_num_elems;
			msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
			uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

			// Now, receive and process next data chunk until all data is processed
			uint32_t num_elems_rem = num_elems;
			uint32_t num_elems_rcvd = 0;
			while(num_elems_rcvd != num_elems)
			{
				size_t to_read_elems = 0;
				if(num_elems_rem < csz)
				{
					to_read_elems = num_elems_rem;
				}
				else
				{
					to_read_elems = csz;
				}
		
				// Receive data (encrypted)
				uint8_t* ciphertext;
				size_t ciphertext_len;
				msgio->read_bin((void**) &ciphertext, &ciphertext_len);

				// Make an ECALL to decrypt the data and process it inside the Enclave
				enclave_decrypt_update_cms(eid, ra_ctx, ciphertext, ciphertext_len);
			
				num_elems_rcvd = num_elems_rcvd +  to_read_elems;
				num_elems_rem = num_elems_rem - to_read_elems;

				// We've processed the secret data, now either clean it up or use data sealing for a second pass later
				delete[] ciphertext;
			}
		}
	}
	// Row update is enabled
	else
	{
		for(i = 0; i < num_files; i++)
		{
			fprintf(stderr, "First Pass, processing file: %lu ...\n", (unsigned long) i);

			// First, receive the total number of elements to be received
			uint8_t* num_elems_buf;
			size_t len_num_elems;
			msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
			uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

			// Now, receive and process next data chunk until all data is processed
			uint32_t num_elems_rem = num_elems;
			uint32_t num_elems_rcvd = 0;
			while(num_elems_rcvd != num_elems)
			{
				size_t to_read_elems = 0;
				if(num_elems_rem < csz)
				{
					to_read_elems = num_elems_rem;
				}
				else
				{
					to_read_elems = csz;
				}
		
				// Receive data (encrypted)
				uint8_t* ciphertext;
				size_t ciphertext_len;
				msgio->read_bin((void**) &ciphertext, &ciphertext_len);

				// Make an ECALL to decrypt the data and process it inside the Enclave
				enclave_decrypt_update_cms_row(eid, ra_ctx, ciphertext, ciphertext_len);
			
				num_elems_rcvd = num_elems_rcvd +  to_read_elems;
				num_elems_rem = num_elems_rem - to_read_elems;

				// We've processed the secret data, now either clean it up or use data sealing for a second pass later
				delete[] ciphertext;
			}
		}
		enclave_normalize_cms_st_length(eid);
	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (CMS) took: %lf seconds\n", duration);

	// Initialize the min-heap within the enclave
	enclave_init_mh(eid, l);

	// Restart timer
	start = std::clock();

	// Second Pass: Query the CMS structure
	fprintf(stderr, "Second pass, querying CMS ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
	uint32_t num_elems_rem = num_elems;
	uint32_t num_elems_rcvd = 0;
	while(num_elems_rcvd != num_elems)
	{
		size_t to_read_elems = 0;
		if(num_elems_rem < csz)
		{
			to_read_elems = num_elems_rem;
		}
		else
		{
			to_read_elems = csz;
		}
		
		// Receive data (encrypted)
		uint8_t* ciphertext;
		size_t ciphertext_len;
		msgio->read_bin((void**) &ciphertext, &ciphertext_len);

		// Make an ECALL to decrypt the data and process it inside the Enclave
		enclave_decrypt_query_cms(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Make a final ECALL to receive the results and report results
	if(k <= 0)
	{
		uint32_t top_ids[l];
                uint16_t acdiff_vals[l];
		//uint16_t test[10];
		//enclave_get_test_buf(eid, test);
                enclave_get_mh_ids(eid, top_ids, l);
                enclave_get_mh_vals(eid, acdiff_vals, l);
		/*for(int i = 0; i < 10; i++)
                {
                        fprintf(stderr, "%u\n", test[i]);
                }*/

                FILE* file = fopen(ofn, "w");
                fprintf(file, "SNP_ID\tALLELE_CNT_DIFF_VAL\n");
                for(int i = 0; i < l; i++)
                {
                        fprintf(file, "%u\t%u\n", top_ids[i], acdiff_vals[i]);
                }
                fclose(file);
                duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
                fprintf(stderr, "Second Pass (CMS) took: %lf seconds\n", duration);
        }
	else
	{
		duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
		fprintf(stderr, "Second Pass (CSK) took: %lf seconds\n", duration);

		start = std::clock();
		fprintf(stderr, "Third pass, querying MH ...\n");
		enclave_init_sketch_rhht(eid, l);
		for(i = 0; i < num_files; i++)
		{
			fprintf(stderr, "Processing file: %lu ...\n", (unsigned long) i);

			// First, receive the total number of elements to be received
			uint8_t* num_elems_buf;
			size_t len_num_elems;
			msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
			uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

			// Now, receive and process next data chunk until all data is processed
			uint32_t num_elems_rem = num_elems;
			uint32_t num_elems_rcvd = 0;
			while(num_elems_rcvd != num_elems)
			{
				size_t to_read_elems = 0;
				if(num_elems_rem < csz)
				{
					to_read_elems = num_elems_rem;
				}
				else
				{
					to_read_elems = csz;
				}

				// Receive data (encrypted)
				uint8_t* ciphertext;
				size_t ciphertext_len;
				msgio->read_bin((void**) &ciphertext, &ciphertext_len);

				// Make an ECALL to decrypt the data and process it inside the Enclave
				enclave_decrypt_process_sketch_rhht(eid, ra_ctx, ciphertext, ciphertext_len);
				num_elems_rcvd = num_elems_rcvd +  to_read_elems;
				num_elems_rem = num_elems_rem - to_read_elems;

				// We've processed the secret data, now either clean it up or use data sealing for a second pass later
				delete[] ciphertext;
			}
		}

		// Make an ECALL to perform the chi-squared test
		rhht_init_chi_sq(eid, case_count, control_count, k);

		// Make an ECALL to receive the result
		uint32_t top_ids[k];
		float chi_sq_vals[k];
		enclave_get_id_buf(eid, top_ids, k);
		enclave_get_res_buf(eid, chi_sq_vals, k);
		FILE* file = fopen(ofn, "w");
		fprintf(file, "SNP_ID\tCHI_SQ_VAL\n");
		for(int i = 0; i < k; i++)
		{
			fprintf(file, "%u\t%.4f\n", top_ids[i], chi_sq_vals[i]);
		}
		fclose(file);

		// Stop timer and report time for the third pass over the data
		duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
		fprintf(stderr, "Third Pass (RHHT/MH) took: %lf seconds\n", duration);
	}
}

/*void app_cms_mt(MsgIO* msgio, config_t& config)
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
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
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
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

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
	msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
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
		msgio->read_bin((void**) &ciphertext, &ciphertext_len);

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
	
}*/

/*void app_cms_mt_ca(MsgIO* msgio, config_t& config)
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
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
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
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

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
	msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
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
		msgio->read_bin((void**) &ciphertext, &ciphertext_len);

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
}*/

/*void app_csk_mt(MsgIO* msgio, config_t& config)
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
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
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
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

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
	msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
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
		msgio->read_bin((void**) &ciphertext, &ciphertext_len);

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
}*/

void app_svd_mcsk(MsgIO* msgio, config_t& config, uint32_t nf, uint32_t nf_case, uint32_t csz, int l, char *ofn, \
	int k, int w, int d, int num_pc, float eps)
{
	// Get the Enclave ID from the configuration
	auto& eid = config.eid;

	// Get the Remote Attestation context from the configuration
	auto& ra_ctx = config.ra_ctx;

	// Make an ECALL to initialize the Enclave CSK structure
	enclave_init_mcsk(eid, nf, num_pc, eps);

	// DEBUG: Print SGX memory usage
//	uint32_t* mem_usage;
//	mem_usage = (uint32_t*) malloc(sizeof(uint32_t));
//	enclave_get_mem_used(eid, mem_usage);
//	fprintf(stderr, "%lu\n", (unsigned long) mem_usage[0]);
//	free(mem_usage);

	// Set app specific variables
	uint32_t num_files = nf;
        uint32_t num_case_files = nf_case;
        uint32_t num_control_files = nf - nf_case;
        uint32_t case_count = (num_case_files << 1);
        uint32_t control_count = (num_control_files << 1);

	// Start timer
	std::clock_t start;
	double duration;
	start = std::clock();

	// First Pass: Update the MCSK structure
	size_t i;
	fprintf(stderr, "First Pass, updating MCSK ...\n");
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "First pass, processing file: %lu ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < csz)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = csz;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			enclave_decrypt_update_mcsk(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}
	
	// Reset file_idx
	enclave_reset_file_idx(eid);

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "First Pass (MCSK) took: %lf seconds\n", duration);

	// Restart timer
	start = std::clock();

	// Perform mean centering before SVD
	enclave_mcsk_mean_centering(eid);

	// DEBUG
//	mcsk_pull_row(eid);
//	float my_res[2001];
//	enclave_get_mcsk_res(eid, my_res);
//	for(int i = 0; i < 2001; i++)
//	{
//		fprintf(stderr, "%f\n", my_res[i]);
//	}

	// SVD
	enclave_svd(eid);

	// DEBUG: memory usage
//	enclave_get_mem_used(eid, mem_usage);
//	fprintf(stderr, "%lu\n", (unsigned long) mem_usage[0]);
//	free(mem_usage);

	// DEBUG
//	float my_eig_res[4000];
//	enclave_get_eig_buf(eid, my_eig_res);
//	for(int i = 0; i < 2000; i++)
//	{
//		fprintf(stderr, "%f\t%f\n", my_eig_res[i], my_eig_res[i + 2000]);
//	}

//	float my_ortho_res[6];
//	enclave_ortho(eid, my_ortho_res);
//	for(int i = 0; i < 6; i++)
//	{
//		fprintf(stderr, "%f\n", my_ortho_res[i]);
//	}

	// DEBUG
//	float my_res[2000];
//	enclave_get_mcsk_sigma(eid, my_res);
//	for(int i = 0; i < 2000; i++)
//	{
//		fprintf(stderr, "%f\n", my_res[i]);
//	}

	// Stop timer and report time for the first pass over the data
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "SVD took: %lf seconds\n", duration);

	// Restart timer
	start = std::clock();

	// Make an ECALL to initialize the Enclave CSK structure
	enclave_init_csk_f(eid, w, d);

	// Second Pass: Update the CSK structure
	fprintf(stderr, "Second Pass, updating CSK ...\n");
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Second pass, processing file: %lu ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < csz)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = csz;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			enclave_decrypt_update_csk_f(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}

	// Reset file_idx
	enclave_reset_file_idx(eid);

	// Stop timer and report time for the second pass over the data
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Second Pass (CSK) took: %lf seconds\n", duration);

	// Restart timer
	start = std::clock();

	// Initialize the min-heap within the enclave
	enclave_init_mh_f(eid, l);

	// Third Pass: Query the CSK structure
	fprintf(stderr, "Third pass, querying CSK ...\n");

	// First, receive the total number of elements to be received
	uint8_t* num_elems_buf;
	size_t len_num_elems;
	msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
	uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

	// Now, receive and process next data chunk until all data is processed
	uint32_t num_elems_rem = num_elems;
	uint32_t num_elems_rcvd = 0;
	while(num_elems_rcvd != num_elems)
	{
		size_t to_read_elems = 0;
		if(num_elems_rem < csz)
		{
			to_read_elems = num_elems_rem;
		}
		else
		{
			to_read_elems = csz;
		}
		
		// Receive data (encrypted)
		uint8_t* ciphertext;
		size_t ciphertext_len;
		msgio->read_bin((void**) &ciphertext, &ciphertext_len);

		// Make an ECALL to decrypt the data and process it inside the Enclave
		enclave_decrypt_query_csk_f(eid, ra_ctx, ciphertext, ciphertext_len);
		num_elems_rcvd = num_elems_rcvd +  to_read_elems;
		num_elems_rem = num_elems_rem - to_read_elems;

		// We've processed the secret data, now either clean it up or use data sealing for a second pass later
		delete[] ciphertext;
	}

	// Stop timer and report time for the second pass over the data
	duration = (std::clock() - start ) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Third Pass (CSK) took: %lf seconds\n", duration);

	// DEBUG
//	uint32_t my_ids[1000];
//	float my_counts[1000];
//	enclave_get_id_buf(eid, my_ids);
//	enclave_get_countf_buf(eid, my_counts);
//	for(int i = 0; i < 1000; i++)
//	{
//		fprintf(stderr, "%lu\t%f\n", (unsigned long) my_ids[i], my_counts[i]);
//	}

	// Last Pass: Use rhht and mh for pcc
	fprintf(stderr, "Last pass, C-A Trend Test ...\n");
	enclave_init_rhht_pcc(eid, l);
	for(i = 0; i < num_files; i++)
	{
		fprintf(stderr, "Processing file: %lu ...\n", i);

		// First, receive the total number of elements to be received
		uint8_t* num_elems_buf;
		size_t len_num_elems;
		msgio->read_bin((void**) &num_elems_buf, &len_num_elems);
		uint32_t num_elems = ((uint32_t*) num_elems_buf)[0];

		// Now, receive and process next data chunk until all data is processed
		uint32_t num_elems_rem = num_elems;
		uint32_t num_elems_rcvd = 0;
		while(num_elems_rcvd != num_elems)
		{
			size_t to_read_elems = 0;
			if(num_elems_rem < csz)
			{
				to_read_elems = num_elems_rem;
			}
			else
			{
				to_read_elems = csz;
			}
		
			// Receive data (encrypted)
			uint8_t* ciphertext;
			size_t ciphertext_len;
			msgio->read_bin((void**) &ciphertext, &ciphertext_len);

			// Make an ECALL to decrypt the data and process it inside the Enclave
			enclave_decrypt_process_rhht_pcc(eid, ra_ctx, ciphertext, ciphertext_len);
			num_elems_rcvd = num_elems_rcvd +  to_read_elems;
			num_elems_rem = num_elems_rem - to_read_elems;

			// We've processed the secret data, now either clean it up or use data sealing for a second pass later
			delete[] ciphertext;
		}
	}
	

	// Make an ECALL to perform the chi-squared test
	rhht_init_cat_chi_sq(eid, num_files, k);
	//abort();

	// Make an ECALL to receive the result
	uint32_t top_ids[k];
	float chi_sq_vals[k];
	enclave_get_id_buf(eid, top_ids, k);
	enclave_get_res_buf(eid, chi_sq_vals, k);
	FILE* file = fopen(ofn, "w");
	fprintf(file, "SNP_ID\tTREND_CHI_SQ_VAL\n");
	for(int i = 0; i < k; i++)
	{
		fprintf(file, "%u\t%.4f\n", top_ids[i], chi_sq_vals[i]);
	}
	fclose(file);

	// Stop timer and report time for the last pass over the data
	duration = (std::clock() - start) / (double) CLOCKS_PER_SEC;
	fprintf(stderr, "Last Pass (C-A Trend Test) took: %lf seconds\n", duration);
}

void new_parse(char* param_path, app_parameters** params, config_t& config)
{
	FILE* param_file;
	char buf[1024];
	char var_name[256];

//	sgx_launch_token_t token = { 0 };
//	sgx_status_t status;
//	sgx_enclave_id_t eid = 0;
//	int updated = 0;
//	int sgx_support;
	uint32_t i;
//	EVP_PKEY* service_public_key = NULL;
	char have_spid = 0;
//	char flag_stdio = 0;

	// Create a logfile to capture debug output and actual msg data
	fplog = create_logfile("client.log");
	dividerWithText(fplog, "Client Log Timestamp");

	const time_t timeT = time(NULL);
	struct tm lt;

	localtime_r(&timeT, &lt);
	fprintf(fplog, "%4d-%02d-%02d %02d:%02d:%02d\n", lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec);
	divider(fplog);

	memset(&config, 0, sizeof(config));
	config.mode = MODE_ATTEST;

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
				else if(strcmp(var_name, "OUTPUT_FILE") == 0)
				{
					(*params)->output_file = (char*) malloc(sizeof(char) * (strlen(token) + 1));
					strncpy((*params)->output_file, token, strlen(token) + 1);
				}
				else if(strcmp(var_name, "NUM_FILES") == 0)
				{
					(*params)->num_files = atoi(token);
				}
				else if(strcmp(var_name, "NUM_CASE_FILES") == 0)
				{
					(*params)->num_files_case = atoi(token);
				}
				else if(strcmp(var_name, "NUM_TOP_SNPS") == 0)
				{
					(*params)->k = atoi(token);
				}
				else if(strcmp(var_name, "CHUNK_SIZE") == 0)
				{
					(*params)->chunk_size = atoi(token);
				}
				else if(strcmp(var_name, "HASH_OPTION") == 0)
				{
					if(strcmp((*params)->app_mode, "basic") != 0)
					{
						fprintf(stderr, "The parameter HASH_OPTION is applicable only in mode basic.\n");
						exit(1);
					}
					if(strcmp(token, "oa") == 0)
					{
						(*params)->hash_option = 0;
					}
					if(strcmp(token, "cmtf") == 0)
					{
						(*params)->hash_option = 2;
					}
				}
				else if(strcmp(var_name, "SKETCH_MODE") == 0)
				{
					if(strcmp((*params)->app_mode, "sketch") != 0)
					{
						fprintf(stderr, "The parameter SKETCH_MODE is applicable only in mode sketch.\n");
						exit(1);
					}
					if(strcmp(token, "cms") == 0)
					{
						(*params)->sketch_mode = 0;
					}
				}
				else if(strcmp(var_name, "SKETCH_WIDTH") == 0)
				{
					if((strcmp((*params)->app_mode, "sketch") != 0) &&
						(strcmp((*params)->app_mode, "pca_sketch") != 0))
					{
						fprintf(stderr, "The parameter SKETCH_WIDTH is applicable only in mode sketch.\n");
						exit(1);
					}
					(*params)->sketch_width = (1 << atoi(token));
				}
				else if(strcmp(var_name, "SKETCH_DEPTH") == 0)
				{
					if((strcmp((*params)->app_mode, "sketch") != 0) &&
						(strcmp((*params)->app_mode, "pca_sketch") != 0))
					{
						fprintf(stderr, "The parameter SKETCH_DEPTH is applicable only in mode sketch.\n");
						exit(1);
					}
					(*params)->sketch_depth = atoi(token);
				}
				else if(strcmp(var_name, "NUM_PC") == 0)
				{
					if(strcmp((*params)->app_mode, "pca_sketch") != 0)
					{
						fprintf(stderr, "The parameter NUM_PC is applicable only in mode pca_sketch.\n");
						exit(1);
					}
					(*params)->num_pc = atoi(token);
				}
				else if(strcmp(var_name, "EPSILON") == 0)
				{
					if(strcmp((*params)->app_mode, "pca_sketch") != 0)
					{
						fprintf(stderr, "The parameter NUM_PC is applicable only in mode pca_sketch.\n");
						exit(1);
					}
					(*params)->eps = atof(token);
				}
				else if(strcmp(var_name, "NUM_TOP_CAND") == 0)
				{
					if((strcmp((*params)->app_mode, "sketch") != 0) &&
						(strcmp((*params)->app_mode, "pca_sketch") != 0))
					{
						fprintf(stderr, "The parameter NUM_TOP_CAND is applicable only in mode sketch.\n");
						exit(1);
					}
					(*params)->l = (1 << atoi(token));
				}
				else if(strcmp(var_name, "SKETCH_ROW_UPDATE") == 0)
				{
					if(strcmp((*params)->app_mode, "sketch") != 0)
					{
						fprintf(stderr, "The parameter SKETCH_ROW_UPDATE is applicable only in mode sketch.\n");
						exit(1);
					}
					(*params)->sketch_rup = atoi(token);
				}
				else if(strcmp(var_name, "SKETCH_CAND_ONLY") == 0)
				{
					if(strcmp((*params)->app_mode, "sketch") != 0)
					{
						fprintf(stderr, "The parameter SKETCH_CAND_ONLY is applicable only in mode sketch.\n");
						exit(1);
					}
					(*params)->sketch_cand_only = atoi(token);
				}
				else if(strcmp(var_name, "SPID") == 0)
				{
					if(strlen(token) < 32)
					{
						fprintf(stderr, "SPID must be 32-byte hex string\n");
						exit(1);
					}

					if(!from_hexstring((unsigned char*) &config.spid, (unsigned char*) token, 16))
					{
						fprintf(stderr, "SPID must be 32-byte hex string\n");
						exit(1);
					}
					have_spid = 1;
				}
				else if(strcmp(var_name, "RANDOM_NONCE") == 0)
				{
					int rand_nonce = atoi(token);
					if(rand_nonce == 1)
					{
						for(i = 0; i < 2; ++i)
						{
							int retry = 10;
							unsigned char ok = 0;
							uint64_t* np= (uint64_t*) &config.nonce;

							while(!ok && retry) ok = _rdrand64_step(&np[i]);
							if(ok == 0)
							{
								fprintf(stderr, "nonce: RDRAND underflow\n");
								exit(1);
							}
						}
						SET_OPT(config.flags, OPT_NONCE);
					}
				}
				else
				{
					fprintf(stderr, "Unknown parameter %s in configuration file.\n", var_name);
					exit(1);
				}
				token_cnt = 0;
			}
			token = strtok(NULL, "=");
		}
	}

	config.server = strdup("127.0.0.1");

/*	if(!have_spid && !config.mode == MODE_EPID )
	{
		fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
		exit(1);
    }*/

	// Can we run SGX?
/*
#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if(sgx_support & SGX_SUPPORT_NO)
	{
		fprintf(stderr, "This system does not support Intel SGX.\n");
        exit(1);
    }
	else
	{
		if(sgx_support & SGX_SUPPORT_ENABLE_REQUIRED)
		{
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
            exit(1);
		}
		else if(sgx_support & SGX_SUPPORT_REBOOT_REQUIRED)
		{
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			exit(1);
		}
		else if(!(sgx_support & SGX_SUPPORT_ENABLED))
		{
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			exit(1);
		}
	} 
#endif
*/
	//close_logfile(fplog);
	fclose(param_file);
}

int main(int argc, char** argv)
{
	// Parse the parameters
	config_t config;
	app_parameters* params;
	init_app_params(&params);
	new_parse(argv[1], &params, config);
	print_app_params(params);

	// If necessray parameters are missing, exit.
	if(params->app_mode == NULL || params->output_file == NULL)
	{
		fprintf(stderr, "Missing parameters.\n");
		exit(1);
	}

	MsgIO* msgio;
	//parse(argv[0], NULL, config);

	if(!remote_attestation(config, &msgio))
	{
		if(strcmp(params->app_mode, "basic") == 0)
		{
			switch(params->hash_option)
			{
				case 0:
					app_oa(msgio, config, params->num_files, params->num_files_case, \
						params->chunk_size, params->k, params->output_file);
					break;
				case 2:
					app_cmtf(msgio, config, params->num_files, params->num_files_case, \
						params->chunk_size, params->k, params->output_file);
					break;

				default:
					app_rhht(msgio, config, params->num_files, params->num_files_case, \
						params->chunk_size, params->k, params->output_file);
					break;
			}
		}
		else if(strcmp(params->app_mode, "sketch") == 0)
		{
			switch(params->sketch_mode)
			{
				case 0:
					if(params->sketch_cand_only == 1)
					{
						app_cms(msgio, config, params->num_files, params->num_files_case, \
							params->chunk_size, params->l, params->output_file, \
							0, params->sketch_width, params->sketch_depth, params->sketch_rup);
					}
        				else
					{
						app_cms(msgio, config, params->num_files, params->num_files_case, \
							params->chunk_size, params->l, params->output_file, \
							params->k, params->sketch_width, params->sketch_depth, \
							params->sketch_rup);
					}
					break;
				default:
					if(params->sketch_cand_only == 1)
					{
						app_csk(msgio, config, params->num_files, params->num_files_case, \
							params->chunk_size, params->l, params->output_file, \
							0, params->sketch_width, params->sketch_depth, params->sketch_rup);
					}
        				else
					{
						app_csk(msgio, config, params->num_files, params->num_files_case, \
							params->chunk_size, params->l, params->output_file, \
							params->k, params->sketch_width, params->sketch_depth, \
							params->sketch_rup);
					}
					break;
			}
		}

		/*else if(strcmp(app_mode, "cms_mt") == 0)
		{
			app_cms_mt(msgio, config);
		}
		else if(strcmp(app_mode, "cms_mt_ca") == 0)
		{
			app_cms_mt_ca(msgio, config);
		}
		else if(strcmp(app_mode, "csk_mt") == 0)
		{
			app_csk_mt(msgio, config);
		}
		else if(strcmp(app_mode, "sketch_rhht") == 0)
		{
			app_sketch_rhht(msgio, config);
		}*/
		else if(strcmp(params->app_mode, "pca_sketch") == 0)
		{
			float epsilon = params->eps * params->eps;
			if(params->num_pc / epsilon > 8192)
			{
				fprintf(stderr, "Temporarily not supporting this range of parameters.\n");
				exit(1);
			}
			app_svd_mcsk(msgio, config, params->num_files, params->num_files_case, \
					params->chunk_size, params->l, params->output_file, \
					params->k, params->sketch_width, params->sketch_depth, \
					params->num_pc, epsilon);
		}

		finalize(msgio, config);
	}
}
