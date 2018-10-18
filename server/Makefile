######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_PRERELEASE ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O3
endif

######## App Settings ########

CXX := g++
Urts_Library_Name := sgx_urts
OpenSSL_Path := /opt/openssl/1.1.0i
App_C_Files := $(wildcard src/*.cpp) $(wildcard src/*.c)
App_Include_Paths :=-I$(SGX_SDK)/include -I$(OpenSSL_Path)/include -Iinclude -IEnclave  -I. 
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -g
App_Cpp_Flags := -std=c++11 $(SGX_COMMON_CFLAGS) -fpermissive -fPIC -Wno-attributes $(App_Include_Paths) -g

ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -L$(OpenSSL_Path)/lib \
    -Wl,-rpath=$(OpenSSL_Path)/lib \
    -l$(Urts_Library_Name) -Wl,-Bstatic -lsgx_capable -Wl,-Bdynamic -lsgx_ukey_exchange -lpthread -ldl -lcurl -lssl -lcrypto -Wl,--as-needed

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_C_Objects := $(patsubst src/%.cpp,obj/%.o,$(patsubst src/%.c,obj/%.o,$(App_C_Files)))

App_Name := app

######## Enclave Settings ########

SGX_SSL_Dir = /opt/intel/sgxssl
OPENSSL_LIBRARY_PATH = $(SGX_SSL_Dir)/lib64
Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
Crypto_Library_Name := sgx_tcrypto
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto 

Enclave_C_Files := Enclave/Enclave.cpp Enclave/app.cpp Enclave/enclave_crypto.cpp Enclave/enclave_rhht.cpp Enclave/enclave_cmtf.cpp

Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -Iinclude -I$(SGX_SSL_Dir)/include
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) -g

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive -l$(OpenSSL_Crypto_Library_Name)
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) -L.\
	$(SgxSSL_Link_Libraries) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name)  -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \

Enclave_C_Objects := $(patsubst Enclave/%.cpp,obj/%.o,$(patsubst Enclave/%.c,obj/%.o,$(Enclave_C_Files)))
Enclave_Name := Enclave.so
Signed_Enclave_Name := Enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

all: $(App_Name) $(Signed_Enclave_Name)

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

src/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd src && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

obj/Enclave_u.o: src/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CXX   <=  $<"

obj/%.o: src/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

obj/%.o: src/%.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): obj/Enclave_u.o $(App_C_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

obj/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

obj/%.o: Enclave/%.cpp
	$(CXX) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(Enclave_Name): obj/Enclave_t.o $(Enclave_C_Objects)
	$(CXX) $^ -o $@ $(Enclave_Link_Flags) 
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) src/Enclave_u.* $(Enclave_C_Objects) Enclave/Enclave_t.* 
