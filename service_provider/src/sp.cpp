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

void app(MsgIO *msgio)
{
    // Encrypt a plaintext 
    char* plaintext = "The quick brown fox jumps over the lazy dog";
    fprintf(stderr, "Plaintext: %s\n", plaintext);
    msgio->send_bin_encrypted(plaintext, strlen(plaintext)+1);

    // Send big test data
    fprintf(stderr, "Send big test data\n");
    constexpr long long N = 1024*1024*1024;
    auto test_data = new uint8_t[N];
    memset(test_data, 1, N);
    msgio->send_bin(test_data, N);
    delete test_data;
}

int main(int argc, char *argv[]) {

    config_t config;
    MsgIO *msgio;
    parse(argv[0], argv[1], config);
    if(!connect(config, &msgio)) 
    {
        remote_attestation(config, msgio);
        app(msgio);
        finalize(msgio, config);
    }
    return 0;
}
