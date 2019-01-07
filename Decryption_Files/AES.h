#ifndef AES_H
#define AES_H

#include <string>
#include <openssl/evp.h>
#include "Converter.h"

class AES
{
private:
	EVP_CIPHER_CTX* de;
	Converter converter;
	void convert_String_To_Hex(const char* inputString, int strlen, unsigned char* finalOutput);
	std::string convert_Hex_To_String(unsigned char* input, int str_len);
	int count_chars_in_str(const char* str);
public:
	AES();
	~AES();
	bool DecryptTAM1(std::string encryptedText, std::string key, std::string iChallenge);
	std::string DecryptTAM2(std::string encryptedText, std::string key, std::string iChallenge, int memoryBankSize);
};

#endif
