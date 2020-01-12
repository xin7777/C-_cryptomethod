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


//Encode with  base64
inline bool Base64Encode( const string & input, string * output )
{
        typedef base64_from_binary<transform_width<string::const_iterator, 6, 8>> Base64EncodeIterator;
        stringstream result;
        try {
                copy( Base64EncodeIterator( input.begin() ), Base64EncodeIterator( input.end() ), ostream_iterator<char>( result ) );
        } catch ( ... ) {
                return false;
        }
        size_t equal_count = (3 - input.length() % 3) % 3;
        for ( size_t i = 0; i < equal_count; i++ )
        {
                result.put( '=' );
        }
        *output = result.str();
        return output->empty() == false;
}



//avoid add extra char at the end
inline std::string decode64(const std::string &val) {
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(val)), It(std::end(val))), [](char c) {
        return c == '\0';
    });
}

//which has some base64Docode bugs
inline bool Base64Decode( const string & input, string * output )
{
        typedef transform_width<binary_from_base64<string::const_iterator>, 8, 6> Base64DecodeIterator;
        stringstream result;
        try {
                copy( Base64DecodeIterator( input.begin() ), Base64DecodeIterator( input.end() ), ostream_iterator<char>( result ) );
        } catch ( ... ) {
                return false;
        }
        *output = result.str();
        return output->empty() == false;
}


//签名 use private key
inline std::string SignRSAKeyFile( const std::string& strPemFileName, std::string& strData )
{
        if (strPemFileName.empty() || strData.empty())
        {
                assert(false);
                return "";
        }
        FILE* hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
        if( hPriKeyFile == NULL )
        {
                assert(false);
                return "";
        }
        std::string strRet;
        RSA* pRSAPriKey = RSA_new();
        if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
        {
                assert(false);
                return "";
        }

        int nLen = RSA_size(pRSAPriKey);
        char* pEncode = new char[nLen + 1];
        unsigned int outlen;
        int ret = RSA_sign(NID_sha1, (const unsigned char*)strData.c_str(), strData.length() , (unsigned char*)pEncode, &outlen, pRSAPriKey);
        if (ret >= 0)
        {
                strRet = std::string(pEncode);
                //std::cout << "\n" << strRet << endl;
                //std::cout << "next \n" << pEncode << endl;
                std::cout << "critical sha length:\n" << outlen << endl;
        }
        if( ret != 1)
                std::cout << "sign failed\n";
        delete[] pEncode;
        RSA_free(pRSAPriKey);
        fclose(hPriKeyFile);
        CRYPTO_cleanup_all_ex_data();
        return strRet;
}


//验证签名 use pubkey
inline int VerifyRSAKeyFile( const std::string& strPemFileName, const std::string& strData , const std::string& sign_data)
{
        if (strPemFileName.empty() || strData.empty())
        {
                assert(false);
                return 0;
        }
        FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
        if( hPubKeyFile == NULL )
        {
                assert(false);
                return 0;
        }
        std::string strRet;
        RSA* pRSAPublicKey = RSA_new();
        if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
        {
                assert(false);
                return 0;
        }

        int nLen = RSA_size(pRSAPublicKey);
        char* pEncode = new char[nLen + 1];
        unsigned int outlen;
        //string testkey(pRSAPublicKey);

        int ret = RSA_verify(NID_sha1, (const unsigned char*)strData.c_str(), strlen(strData.c_str()),  (const unsigned char*)sign_data.c_str(), 128,  pRSAPublicKey);
        if(ret != 1){
                std::cout << "verify error\n";
                unsigned long ulErr = ERR_get_error();
                char szErrMsg[1024] = {0};
                cout << "error number:" << ulErr << endl;
        char *pTmp = NULL;
        pTmp = ERR_error_string(ulErr,szErrMsg); // 格式：error:errId:库:函数:reason
  
        cout << szErrMsg << endl;
                return -1;
        }
        else
                std::cout << "verify success\n";
        delete[] pEncode;
        RSA_free(pRSAPublicKey);
        fclose(hPubKeyFile);
        CRYPTO_cleanup_all_ex_data();
        return 1;
}


inline std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
{
        if (strPemFileName.empty() || strData.empty())
        {
                assert(false);
                return "";
        }
        FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
        if( hPubKeyFile == NULL )
        {
                assert(false);
                return "";
        }
        std::string strRet;
        RSA* pRSAPublicKey = RSA_new();
        if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
        {
                assert(false);
                return "";
        }

        int nLen = RSA_size(pRSAPublicKey);
        char* pEncode = new char[nLen + 1];
        //std::cout << "FLAG=========FLAG";
        int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
                strRet = std::string(pEncode, ret);
        }
        delete[] pEncode;
        RSA_free(pRSAPublicKey);
        fclose(hPubKeyFile);
        CRYPTO_cleanup_all_ex_data();
        //std::cout << "FLAG=======FLAG:" << strRet <<endl;
        return strRet;
}


inline std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
{
        if (strPemFileName.empty() || strData.empty())
        {
                assert(false);
                return "";
        }
        FILE* hPriKeyFile = fopen(strPemFileName.c_str(),"rb");
        if( hPriKeyFile == NULL )
        {
                assert(false);
                return "";
        }
        std::string strRet;
        RSA* pRSAPriKey = RSA_new();
        if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
        {
                assert(false);
                return "";
        }
        int nLen = RSA_size(pRSAPriKey);
        char* pDecode = new char[nLen+1];

        int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
        if(ret >= 0)
        {
                strRet = std::string((char*)pDecode, ret);
        }
        delete [] pDecode;
        RSA_free(pRSAPriKey);
        fclose(hPriKeyFile);
        CRYPTO_cleanup_all_ex_data();
        return strRet;
}

inline string SHA1_hash(string m){
        //string m = "test";
        //hash SHA1
        unsigned char digest[SHA_DIGEST_LENGTH];

        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, m.c_str(), strlen(m.c_str()));
        SHA1_Final(digest, &ctx);

        char mdString[SHA_DIGEST_LENGTH*2+1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
                sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
        //cout << "digest:" << digest << endl;
        std::cout << "SHA1 digest translate:" << mdString << endl;


        string digest_s((char*)digest);
        string mdString1(mdString);  //十六进制
        return mdString;
        //auto sign_ = SignRSAKeyFile("prikey.pem",mdString1);
        //std::cout << "data:" << sign_ << std::endl;
}


