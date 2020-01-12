#include <iostream>
#include <csignal>
#include <ctime>
#include "TCPServer.h"

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <cassert>
#include <cstring>
#include <bits/stdc++.h>
#include <openssl/sha.h>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string/trim.hpp>

using namespace std;
using namespace boost::archive::iterators;


TCPServer tcp;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 2700;


string SHA1_hash(string m){
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
        cout << "digest:" << digest << endl;
        std::cout << "SHA1 digest translate:" << mdString << endl;


        string digest_s((char*)digest);
        string mdString1(mdString);  //十六进制
	return mdString;
        //auto sign_ = SignRSAKeyFile("prikey.pem",mdString1);
        //std::cout << "data:" << sign_ << std::endl;
}


//验证签名 use pubkey
int VerifyRSAKeyFile( const std::string& strPemFileName, const std::string& strData , const std::string& sign_data)
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
        int ret = RSA_verify(NID_sha1, (const unsigned char*)strData.c_str(), strlen(strData.c_str()),  (const unsigned char*)sign_data.c_str(), 128,  pRSAPublicKey);
	if(ret != 1){
		std::cout << "verify error\n";
		unsigned long ulErr = ERR_get_error();
		char szErrMsg[1024] = {0};  
		cout << "error number:" << ulErr << endl; 
        char *pTmp = NULL;  
        pTmp = ERR_error_string(ulErr,szErrMsg); // 格式：error:errId:库:函数:原因  
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

bool Base64Decode( const string & input, string * output )
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

std::string decode64(const std::string &val) {
    using namespace boost::archive::iterators;
    using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
    return boost::algorithm::trim_right_copy_if(std::string(It(std::begin(val)), It(std::end(val))), [](char c) {
        return c == '\0';
    });
}


std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
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

void close_app(int s) {
	tcp.closed();
	exit(0);
}


vector<string> split(string str, string separator)  
{  
    vector<string> result;  
    int cutAt;  
    while( (cutAt = str.find_first_of(separator)) != str.npos )  
    {  
        if(cutAt > 0)  
        {  
            result.push_back(str.substr(0, cutAt));  
        }  
        str = str.substr(cutAt + 1);  
    }  
    if(str.length() > 0)   
    {  
        result.push_back(str);  
    }  
    return result;  
} 

void * sendFile_client(void * m) { 
        struct descript_socket *desc = (struct descript_socket*) m;

		/*FILE *fp = fopen(desc->message.c_str(),"r");
		if(NULL == fp){
			std::cout << "File:" <<desc->message << "not found!" << std::endl;
		}
		char buffer[4096];
		bzero(buffer,4096);
		int length = 0;

		while((length = fread(buffer,sizeof(char),4096,fp)) > 0){
			if(send(newsockfd[desc->id]->socket,buffer,length,0) < 0)
			{
				std::cout << "Send file failed:" << desc->message <<std::endl;
				break;
			}
			bzero(buffer,4096);
		}
		fclose(fp);
		*/
		tcp.SendFile(desc->message,desc->id);
                //tcp.Send(date, desc->id);
                //sleep(time_send);
       // pthread_exit(NULL);
        return 0;
}


void * send_client(void * m) {
        struct descript_socket *desc = (struct descript_socket*) m;

	while(1) {
		if(!tcp.is_online() && tcp.get_last_closed_sockets() == desc->id) {
			cerr << "Connessione chiusa: stop send_clients( id:" << desc->id << " ip:" << desc->ip << " )"<< endl;
			break;
		}
		std::time_t t = std::time(0);
		std::tm* now = std::localtime(&t);
		int hour = now->tm_hour;
		int min  = now->tm_min;
		int sec  = now->tm_sec;

		std::string date = 
			    to_string(now->tm_year + 1900) + "-" +
			    to_string(now->tm_mon + 1)     + "-" +
			    to_string(now->tm_mday)        + " " +
			    to_string(hour)                + ":" +
			    to_string(min)                 + ":" +
			    to_string(sec)                 + "\r\n";
		cerr << date << endl;
		tcp.Send(date, desc->id);
		//sleep(time_send);
	}
	pthread_exit(NULL);
	return 0;
}

int write_string_to_file_append(const std::string &file_string, const std::string str){
	std::ofstream OsWrite(file_string,std::ofstream::app);
	OsWrite << str;
	//OsWrite << std::endl;
	OsWrite.close();
	return 0;
}


void * received(void * m)
{
        pthread_detach(pthread_self());
	vector<descript_socket*> desc;
	while(1)
	{
		desc = tcp.getMessage();
		static int i = 0;
		for(i; i < desc.size(); i++) {
			//std::cout << "desc.seze = :" << desc.size() <<std::endl;
			if( desc[i]->message == "pubkey1.pem"){
				if(!desc[i]->enable_message_runtime)
                                {
                                        desc[i]->enable_message_runtime = true;
				//send certification1
					sendFile_client((void*)desc[i]);
					//tcp.clean(i);
					//break;
				}
			}
			else if(desc[i]->message == "pubkey2.pem"){
				std::cout << "receive cer2.cer request"<<std::endl;
				desc[i]->enable_message_runtime = true;
				sendFile_client((void*)desc[i]);
				//tcp.clean(i);
				//break;
			}
			//else if( desc[i]->message[0] > 'z' )
			else
			{
					//desc[i]->message.erase(desc[i]->message.begin());
					std::cout << "receive message: " <<std::endl;
					std::cout << desc[i]->message << std::endl;
					std::vector<string> messages = split(desc[i]->message,":");
					//messages0 = M1, messages1 = Hm2, messages2 = Base64(sign(Hm12)),messages3 = pubkey_string(client)
					string sign_Hm12;
					Base64Decode(messages[2], &sign_Hm12);
					std::cout << "M1 base64 ==========:" << messages[0] << endl;
					//Base64Decode(messages[0],&messages[0]);
					messages[0] = decode64(messages[0]);
					//std::cout << "messages[0] debase64:" << messages[0] << endl;
					messages[0] = DecodeRSAKeyFile("../example-client/prikey.pem",messages[0]);
					std::cout << "messages[0]:" << messages[0] << endl;
					string Hm1 = SHA1_hash(messages[0]);
					string Hm2 = messages[1];
					string Hm12 = SHA1_hash(Hm1 + ":" + Hm2);
					//write the pubkey_string to pubkey.pem
					string pubkey_string = messages[3];
					write_string_to_file_append("pubkey.pem",pubkey_string);
					int answer_verify =  VerifyRSAKeyFile("../example-client/pubkey.pem",Hm12,sign_Hm12);  //verify the sign to affirm the validity of m1 and m2;
					std::cout << "\n answer of verify:" << answer_verify << endl;
					//string DecodeM1 = DecodeRSAKeyFile("prikey1.pem",desc[i]->message);
			                //send_client((void *) desc[i]));
					//std::cout << "\n" << "decode string: " << DecodeM1 << endl;
					tcp.Send(to_string(answer_verify), desc[i]->id);
					pthread_exit(NULL);
					//tcp.clean(i);
					//break;
			}
		}
		//usleep(1000);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if(argc < 2) {
		cerr << "Usage: ./server port (opt)time-send" << endl;
		return 0;
	}
	if(argc == 3)
		time_send = atoi(argv[2]);
	std::signal(SIGINT, close_app);

	pthread_t msg;
        vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };

	if( tcp.setup(atoi(argv[1]),opts) == 0) {
		if( pthread_create(&msg, NULL, received, (void *)0) == 0)
		{
			while(1) {
				tcp.accepted();
				cerr << "Accepted" << endl;
			}
		}
	}
	else
		cerr << "Errore apertura socket" << endl;
	return 0;
}
