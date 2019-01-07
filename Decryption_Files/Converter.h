#ifndef CONVERTER_H
#define CONVERTER_H

#include <string>

class Converter
{
public:
	Converter();
	~Converter();
	std::string convert_Hex_To_String(unsigned char* input, int str_len);
	void convert_String_To_Hex(const char* inputString, int strlen, unsigned char* finalOutput);
};

#endif