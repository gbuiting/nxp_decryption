#include "Converter.h"
#include <sstream>

Converter::Converter(){

}

Converter::~Converter(){

}

/*	Converts hexadecimal string to actual hexadecimal values via the ASCII-table. 
	Decryption works with actual HEX values. 
	Example: string x = "ABCD" will be turned into: {0xAB, 0xCD}*/
void Converter::convert_String_To_Hex(const char* inputString, int strlen, unsigned char* finalOutput){
	if (inputString == NULL || inputString == "" || strlen <= 0 || finalOutput == NULL) return;
	unsigned char output[(strlen)/2];
	int outputCounter = 0;

	for (int i = 0; i < strlen - 1; i = i+2)
	{
		char newByte[2] = { inputString[i], inputString[i+1]};
		for (int j = 0; j < sizeof(newByte); ++j)
		{
			char temp = newByte[j];
			if (newByte[j] <= 57 && newByte[j] >= 48){
				newByte[j] = temp - 48;
			}
			else if (newByte[j] <= 70 && newByte[j] >= 65){
				newByte[j] = temp - 55;
			}
			else if (newByte[j] <= 102 && newByte[j] >= 97){
				newByte[j] = temp - 87;
			}
			else return;
		}
		newByte[0] <<= 4;
		newByte[1] |= newByte[0];
		output[outputCounter] = newByte[1];
		outputCounter++;
	}
	for (int i = 0; i < sizeof(output); ++i)
	{
		finalOutput[i] = output[i];
	}
}

/*	Converts hexadecimals to a readable string via the ASCII-table.
	Example: data = {0xAB, 0xCD} will be turned into: string x = "ABCD"*/
std::string Converter::convert_Hex_To_String(unsigned char* input, int str_len){
	if (input == NULL || str_len <= 0) return "";
	std::stringstream ss;

	for (int i = 0; i < str_len; ++i)
	{
		unsigned char chars[2];
		chars[0] = input[i] & 0xf0;
		chars[1] = input[i] & 0x0f;
		chars[0] >>= 4;
		for (int j = 0; j < sizeof(chars); ++j)
		{
			char temp = chars[j];
			if (chars[j] >= 0 && chars[j] <= 9){
				chars[j] = temp + 48;
			}
			else if (chars[j] >= 10 && chars[j] <= 15){
				chars[j] = temp + 55;
			}
			else return NULL;
		}

		ss << chars[0] << chars[1];
	}
	return ss.str();
}