CXX := g++
CXXFLAGS := -O3 -std=c++20 -march=x86-64 -Wall -Wextra -Wno-unused-parameter
LDFLAGS := -static -s
LIBS := -lz

SRCS := src/store.cpp src/git_http.cpp src/rest.cpp src/graphql.cpp src/mcp.cpp src/server.cpp

.PHONY: all clean

all: bin/forge

bin/forge: $(SRCS) src/sha1.hpp src/json.hpp src/http_types.hpp src/store.hpp src/git_http.hpp src/rest.hpp src/graphql.hpp src/mcp.hpp
	mkdir -p bin
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(SRCS) $(LIBS) -o bin/forge

clean:
	rm -rf bin
