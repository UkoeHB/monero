#include <stddef.h>
#include "randomx/src/blake2/blake2.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <boost/algorithm/hex.hpp>

int run_tests(const char* filepath) {
    std::ifstream blake2b_kat(filepath, std::fstream::in);
    if(blake2b_kat.fail()){
        std::cerr << "Cannot open blake2b-kat.txt file, given path : " << filepath << std::endl;
    }

    int i = 0;
    while(true)
    {
        char in[1024] = {0};
        size_t inlen = 0;
        char out[BLAKE2B_OUTBYTES] = {0};
        char key[BLAKE2B_KEYBYTES] = {0};
        size_t keylen = 0;
        char hash[64] = {0};
        std::string t; // t as in temporary

        blake2b_kat >> std::skipws >> t; // throw away "in:"
        if(t.empty()) {
            break; // end of file
        }
        else if(i) { // first hash record special, does not have any "in:" value
            blake2b_kat >> std::skipws >> t; // actual in
            t = boost::algorithm::unhex(t);
            std::copy(t.begin(), t.end(), in);
            inlen = t.size();
        }
        ++i;

        blake2b_kat >> std::skipws >> t; // throw away "key:"
        blake2b_kat >> std::skipws >> t; // actual keybytes
        t = boost::algorithm::unhex(t);
        std::copy(t.begin(), t.end(), key);

        blake2b_kat >> std::skipws >> t; // throw away "hash:""
        blake2b_kat >> std::skipws >> t; // actual hashbytes
        t = boost::algorithm::unhex(t);
        std::copy(t.begin(), t.end(), hash);

        int ret = blake2b(out, BLAKE2B_OUTBYTES, in, inlen, key, BLAKE2B_KEYBYTES);
        if(ret) {
            std::cerr << "blake2b return error.";
            return -1;
        }

        if(!std::equal(std::begin(out), std::end(out), std::begin(hash))){
            std::cerr << "For case number " << i << " computed hash value and given hash value does not match.";
            return -1;
        }

        // Clean up the mess
        memset(in, inlen, sizeof(char));
        memset(out, BLAKE2B_OUTBYTES, sizeof(char));
        memset(hash, BLAKE2B_OUTBYTES, sizeof(char));
        memset(key, BLAKE2B_KEYBYTES, sizeof(char));
    }
    return 0;
}


int main(int argc, char** argv) {
  if(argc != 2) {
    std::cout << "Usage : " << std::endl 
              << "      blake2b-tests PATHTO/blake2b-kats.txt" ;
    return -1; 
  }
  return run_tests(argv[1]);
}