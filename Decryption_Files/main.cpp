#include "AES.h"
#include <openssl/evp.h>
#include <string>
#include <iostream>
#include <unistd.h>

int main(int argc, char const *argv[])
{
	AES* decryptAES = new AES();
	//TAM1 authentication
	std::string encrypted_Data_TAM1 = 	"4EDE50BD72F0AEACB532D1677DEB2908";
	std::string key_TAM1 = 				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
	std::string iChallenge_TAM1 =		"E4D3000B55C8C30508FD";

	bool authenticated = decryptAES->DecryptTAM1(encrypted_Data_TAM1, key_TAM1, iChallenge_TAM1);
	if (authenticated){
		std::cout << "Authentication successful" << std::endl;
	}
	else std::cout << "Authentication failed" << std::endl;

	//TAM2 decryption
	std::string encrypted_Data_TAM2 = 	"141585F836BC9D8EAA8F421D34DB902644EBB5B4F917871E060F7848846CD0E3";
	std::string key_TAM2 = 				"11111111111111111111111111111111";
	std::string iChallenge_TAM2 = 		"BDF5340CAC92052B038B";

	std::string x = decryptAES->DecryptTAM2(encrypted_Data_TAM2, key_TAM2, iChallenge_TAM2, 128);
	
	std::cout << x << std::endl;

	//cleanup
	delete(decryptAES);
	return 0;
}