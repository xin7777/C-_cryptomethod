#include "TCPClient.h"
#include "myCrypto.cpp"
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
#include <cassert>
#include <cstring>
#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <sstream>
#include <fstream>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string/trim.hpp>


#include <iostream>
#include <functional>
#include <bits/stdc++.h>
#include <openssl/sha.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
 
#include <iostream>
#include <string>
#include <cstring>
#include <cassert>


//#include "TCPClient.h"
using namespace std;

using namespace boost::archive::iterators;

TCPClient tcp;

void sig_exit(int s)
{
	tcp.exit();
	exit(0);
}

string readFileIntoString(char * filename){
	ifstream ifile(filename);
	// read file content to buf
	ostringstream buf;
	char ch;
	while(buf&&ifile.get(ch))
		buf.put(ch);
	return buf.str();
}


int main(int argc, char *argv[])
{
	string name, tel, address, ip, port;
	if(argc != 11) {
		cerr << "Usage: ./client ip port message" << endl;
		return 0;
	}
	int opt;
	const char *optstring = "i:p:n:t:a:";
	while ((opt = getopt(argc,argv,optstring)) != -1){
		if(opt == 105){
			ip = optarg;
		}
		else if(opt == 112){
			port = optarg;
		}
		else if(opt == 110){
			name = optarg;
		} 
		else if(opt == 116){
                        tel = (optarg);
                }
		else if(opt == 97){
                        address = (optarg);
                }

	}

	std::cout << "name:" << name << endl <<  "tel:" << tel << endl << "address" << address << endl;
	signal(SIGINT, sig_exit);

	tcp.setup(ip,atoi(port.c_str()));

	//send request and receive cer pubkey1.pem is the Server B's pubkey, pubkey2.pem is the Third's pubkey
	tcp.Send("pubkey1.pem");
	char file_name[] = "pubkey1.pem";
	char buffer[4096];
	FILE *fp = fopen(file_name,"w");
	if(NULL == fp){
		std::cout << "Can't open this file to write\n";
		exit(1);
	}
	bzero(buffer, 4096);
	std:: cout << tcp.receiveFile(4096,file_name) << std::endl;
	tcp.exit();
	//send request to receive the pubkey2.pem
	TCPClient tcp;
	tcp.setup(ip,atoi(port.c_str()));
	tcp.Send("pubkey2.pem");
        char file_name2[] = "pubkey2.pem";
        char buffer2[4096];
        FILE *fp2 = fopen(file_name2,"w");
        if(NULL == fp2){
                std::cout << "Can't open this file to write\n";
                exit(1);
        }
        bzero(buffer2, 4096);
        std:: cout << tcp.receiveFile(4096,file_name2) << std::endl;
	tcp.exit();
	//send encode messages
	TCPClient tcp1;
	tcp1.setup(ip,atoi(port.c_str()));
	string M1 = name + '\n' + address;
	string encodeM1 = EncodeRSAKeyFile("pubkey.pem",M1);
	cout << "Encrypted M1(RSA use pubkey1): " << encodeM1 << endl;
	//string DecodeM1 = DecodeRSAKeyFile("prikey.pem",encodeM1);
	//std::cout << "jiemahou:::====" << DecodeM1 << endl << "star:";
	//unsigned char sixM1[1024];
//	for(int i=0;i<encodeM1.length();i++){
//		printf("%02x",encodeM1[i]);
//	}
	string base64_encM1;
	Base64Encode(encodeM1,&base64_encM1);
	std::cout << "Encrypted M1 Base64 encode:" << base64_encM1 << endl;
	/*
	test the base64 decode
	string testM1;
	Base64Decode(base64_encM1,&testM1);
	std::cout << "Debase64**********" << testM1 << endl;
	string outM;
	Base64Encode(testM1, &outM);
	std::cout << "Second base64 encode:" << outM  <<endl;
	cout << "======================================================" << endl;
	string testM2 = decode64(base64_encM1);
	cout << "11111111base64:" << testM2 <<endl;
	Base64Encode(testM2,&outM);
	cout << "222222222222encodebaes64:" << outM << endl;
	*/
	//string testM1 = decode64(base64_encM1);
	//std::cout <<"final answer: decode******" << DecodeRSAKeyFile("prikey.pem",testM1);
	//std::cout << "test M1 :=======================" << testM1 << endl;
	string M2 = tel;
	cout << "Hm1 ";
	string Hm1 = SHA1_hash(M1);
	cout << "Hm2 ";
	string Hm2 = SHA1_hash(M2);
	cout << "Hm12 ";
	string Hm12 = SHA1_hash(Hm1 + ":" + Hm2);
	//std::cout << "\nHm12 SHA1 hash : \n" << Hm12 << endl;
	//string Hm2 = SHA1_hash(tel);
	//encrypt string encodeM1 = EncodeRSAKeyFile("pubkey1.pem", "1"+M1);
	auto sign_data = SignRSAKeyFile("prikey.pem",Hm12);	
	VerifyRSAKeyFile("pubkey.pem",Hm12,sign_data);
	string base64_str; //hash Hm12 string
	Base64Encode(sign_data,&base64_str);
	string pubstring = readFileIntoString("pubkey.pem");
	std::cout << "local pubkey transformed to string ======:" << endl <<pubstring << endl;
	string message = base64_encM1 + ":" +  Hm2  + ":" + base64_str + ":" + pubstring;
	cout << "Send to B:";
	tcp1.Send(message);
	std::cout <<"receive decode:" <<  tcp1.receive() ;
	cout << endl;
	//tcp1.exit();
        //send encode messages
        TCPClient tcp2;
        tcp2.setup(ip,atoi(port.c_str())+1);
	string encodeM2 = EncodeRSAKeyFile("pubkey2.pem",M2);
	cout << "Encrypted M2(RSA use pubkey2):" << encodeM1 << endl;
	string base64_encM2;
	Base64Encode(encodeM2,&base64_encM2);
	cout << "Encrypted M2 Base64 encode:" << base64_encM2 << endl;
	string message2 = base64_encM2 + ":" + Hm1 + ":" + base64_str + ":" + pubstring;
	cout << "Send to C:";
	tcp2.Send(message2);
	std::cout << "receive messages:" << tcp2.receive();
	cout << endl;

	return 0;
}
