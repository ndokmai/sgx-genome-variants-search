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

void app(MsgIO *msgio, config_t& config) 
{

    auto & eid = config.eid;
    auto & ra_ctx = config.ra_ctx;

    unsigned char *ciphertext;
    size_t clen;
    msgio->read_bin(&ciphertext, &clen);
    fprintf(stderr, "IV+Ciphertext: ");
    for(size_t i=0; i<clen; i++) {
        fprintf(stderr, "%02x", ciphertext[i]);
    }
    fprintf(stderr, "\n");

    // plaintext length can't be longer than ciphertext length
    char* plaintext = new char[clen];
    size_t plen;
    uint8_t sk[16] = {0};
    enclave_decrypt_for_me(eid, ra_ctx, (int *)&plen, ciphertext, clen, plaintext, sk);
    fprintf(stderr, "Plaintext: %s\n", plaintext);
    
    fprintf(stderr, "Key: ");
    for(size_t i=0; i<16; i++) {
        fprintf(stderr, "%02x", sk[i]);
    }
    fprintf(stderr, "\n");
    delete plaintext;
    delete ciphertext;

    const size_t BUFFER_SIZE = (1<<6)*1024;
    // Received big test data
    fprintf(stderr, "Receive big test data\n");
    uint8_t *test_data;
    size_t idx=0;
    size_t N;
    msgio->read_bin(&test_data, &N);

    fprintf(stderr, "---- in buffer -----------------------------------------------------------\n");
    long test_sum = 0;
    for(size_t i=0; i<N; i++) {
        test_sum += (long)test_data[i];
    }
    fprintf(stderr, "test sum: %ld\n", test_sum);
    fprintf(stderr, "\n----------------------------------------------------------------------------\n");
    std::clock_t start;
    double duration;
    start = std::clock();
    init_sum_magic(eid);
    while(idx != N) {
        size_t toread_bytes = 0;
        if( N > BUFFER_SIZE ) {
            toread_bytes = BUFFER_SIZE;
        } else {
            toread_bytes = N;
        }
        //fprintf(stderr, "toread: %ld\n", toread_bytes);
        auto status =  enclave_in_function(eid, test_data+idx, toread_bytes);
        //fprintf(stderr, "status: %d\n", status);
        sum_magic(eid);
        idx += toread_bytes;
    }

    long result = 0;
    finalize_sum_magic(eid, &result);
    duration = ( std::clock() - start  ) / (double) CLOCKS_PER_SEC;
    fprintf(stderr, "time: %lf\n", duration);
    fprintf(stderr, "result: %ld\n", result);
}

int main(int argc, char *argv[]) {
    config_t config;
    MsgIO *msgio;
    parse(argv[0], argv[1], config);
    if(!remote_attestation(config, &msgio))
    {
        app(msgio, config);
        finalize(msgio, config);
    }

}
