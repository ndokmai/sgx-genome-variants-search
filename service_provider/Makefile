MAKEFILE_DIR:=$(abspath $(lastword $(MAKEFILE_LIST))/..)
BASE_DIR:=$(abspath $(MAKEFILE_DIR))
SGXSDK_DIR:=/opt/intel/sgxsdk
HTTPPARSER_DIR:=$(BASE_DIR)/httpparser
OPENSSL_DIR:=/opt/openssl/1.1.0i

CXX=g++-7

CXXFLAGS=-std=c++17 -g -fpermissive -Wall


LDFLAGS= -L$(OPENSSL_DIR)/lib \
	 -Wl,--start-group -Wl,-Bstatic \
	 -Wl,-Bdynamic -lcurl -lssl -lcrypto -Wl,--end-group

CXXINCFLAGS=-I. -I$(BASE_DIR)/include -I$(SGXSDK_DIR)/include -I$(OPENSSL_DIR)/include
COMPILE=$(CXX) $(CXXFLAGS) $(CXXINCFLAGS) -c $< -o $@
LINK=$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)
MKDIR=mkdir -p $(dir $@)

SRC=$(wildcard src/*.cpp) $(wildcard src/*.c)
OBJ=$(patsubst src/%.cpp,obj/%.o,$(patsubst src/%.c,obj/%.o,$(SRC)))
OUT=sp

ALL: $(OUT) 

$(OUT): $(OBJ)
	@$(MKDIR)
	$(LINK)

obj/%.o: src/%.cpp
	@$(MKDIR)
	$(COMPILE)

obj/%.o: src/%.c
	@$(MKDIR)
	$(COMPILE)

.PHONY: clean

clean:
	$(RM) $(OBJ)  $(OUT)

