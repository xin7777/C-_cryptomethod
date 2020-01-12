#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <signal.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <sstream>
#include <fstream>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <functional>
#include <bits/stdc++.h>
#include <cstring>
#include <cassert>

using namespace std;
using namespace boost::archive::iterators;

bool Base64Encode(const string & input, string * output){};

std::string decode64(const std::string &val){};

bool Base64Decode(const string & input, string * output){};

std::string SignRSAKeyFile(const std::string& strPemFileName,std::string& strData){};

int VerifyRSAKeyFile(const std::string& strPemFileName, const std::string& strData, const std::string& sign_data){};

std::string EncodeRSAKeyFile(const std::string& strPemFileName,const std::string& strData){};

std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData ){};

string SHA1_hash(string str){};


