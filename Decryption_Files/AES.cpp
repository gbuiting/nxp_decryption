#include <openssl/evp.h>
#include <string>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include "AES.h"

AES::AES(){
	
}

AES::~AES(){
	EVP_CIPHER_CTX_free(de);
}

/* 	Decrypts TAM1. This functions checks if the authentication is correct by checking if the iChallenge
	can be found in the output.
	Returns true if authentication is correct, false if it failed. */
bool AES::DecryptTAM1(std::string encryptedText, std::string key, std::string iChallenge){
	int encryptedText_len = encryptedText.length();
	if (encryptedText_len != 32){
		return false;
	}
	int len;
	de = EVP_CIPHER_CTX_new();

	unsigned char decryptedText[16];
  	unsigned char encryptedTextHex[16];
  	unsigned char keyHex[16];
  	converter.convert_String_To_Hex(encryptedText.c_str(), encryptedText_len, encryptedTextHex);
  	converter.convert_String_To_Hex(key.c_str(), key.length(), keyHex);

  	//initialize and decrypt message
  	if(EVP_DecryptInit_ex(de, EVP_aes_128_ecb(), NULL, keyHex, NULL) != 1)
    	throw std::runtime_error("EVP_DecryptInit_ex failed: TAM1");

  	if(EVP_DecryptUpdate(de, decryptedText, &len, encryptedTextHex, sizeof(encryptedTextHex)) != 1)
    	throw std::runtime_error("EVP_DecryptUpdate failed, TAM1");

    bool authenticated = true;

    if (iChallenge.length() != 20){
    	return false;
    }

    unsigned char iChallengeHex[10];
    converter.convert_String_To_Hex(iChallenge.c_str(), iChallenge.length(), iChallengeHex);

    if (decryptedText[0] == 0x96 && decryptedText[1] == 0xc5)
    {
    	// i starts at 6 because the iChallenge starts at the 6th byte.
    	for (int i = 6; i < sizeof(decryptedText) - 6; ++i)
    	{
    		if (decryptedText[i] != iChallengeHex[i - 6]){
    			authenticated = false;
    			break;
    		}
    	}
    }
    else 
    {
    	authenticated = false;
  	}
  	return authenticated;
}

/* 	Decrypts TAM2. Input the full 64 byte response from the reader. This function will authenticate 
	the first 32 bytes and decrypts the last 32 bytes.  
	Returns a string with the decrypted data 

    MemoryBankSize is the amount of bits to be read from the memory. This is usefull to determine the size of the
   	final output.
   	Memory banks:
   	EPC - most common EPC banks are 96 and 128 bits long, but can extend to 496 bits 
   	TID - TID memory bank is usually between 32 and 80 bits 
   	User memory - User memory is usually 512 bits and upward to 8k in some tags.*/
std::string AES::DecryptTAM2(std::string encryptedText, std::string key, std::string iChallenge, int memoryBankSize){
	int encryptedText_len = encryptedText.length();
	if (encryptedText_len != 64) {
		return "";
	}

	std::string part1 = encryptedText.substr(0, 32);
	std::string part2 = encryptedText.substr(32);

	unsigned char IV[16], encryptedInput[16];
	converter.convert_String_To_Hex(part1.c_str(), part1.length(), IV);
	converter.convert_String_To_Hex(part2.c_str(), part2.length(), encryptedInput);

	//TAM1 authentication
	bool authenticated = DecryptTAM1(part1, key, iChallenge);
	if (!authenticated){
		return "";
	}

	int len;
	unsigned char output[memoryBankSize/8];
	for (int i = 0; i < sizeof(output); ++i)
	{
		output[i] = 0x00;
	}
	unsigned char keyHex[16];
	converter.convert_String_To_Hex(key.c_str(), key.length(), keyHex);

    if (EVP_DecryptInit_ex(de, EVP_aes_128_cbc(), NULL, keyHex, IV) != 1)
      throw std::runtime_error("EVP_DecryptInit_ex failed: TAM2");

    if (EVP_DecryptUpdate(de, output, &len, encryptedInput, sizeof(encryptedInput)) != 1)
      throw std::runtime_error("EVP_DecryptUpdate failed: TAM2");
	
  	std::string outputString = converter.convert_Hex_To_String(output, sizeof(output));

  	return outputString;
}