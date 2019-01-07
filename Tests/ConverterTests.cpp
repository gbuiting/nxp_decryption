#include "../Decryption_Files/Converter.h"
#include <gtest/gtest.h>

Converter converter;

// convert_String_To_Hex Unit tests
TEST(ConvertStringToHexTest, Right_result) {
	std::string inputString = "ABCDEF";
	int inputStringLength = inputString.length();
	unsigned char output[3];
	unsigned char expectedOutput[3] = {0xAB, 0xCD, 0xEF};
	converter.convert_String_To_Hex(inputString.c_str(), inputStringLength, output);
	
	ASSERT_EQ(expectedOutput[0], output[0]);
	ASSERT_EQ(expectedOutput[1], output[1]);
	ASSERT_EQ(expectedOutput[2], output[2]);
}

TEST(ConvertStringToHexTest, input_NULL) {
	std::string inputString;
	int inputStringLength = 6;
	unsigned char output[3];
	unsigned char expectedOutput[3] = {0xAB, 0xCD, 0xEF};
	converter.convert_String_To_Hex(inputString.c_str(), inputStringLength, output);
	
	ASSERT_NE(expectedOutput[0], output[0]);
	ASSERT_NE(expectedOutput[1], output[1]);
	ASSERT_NE(expectedOutput[2], output[2]);
}

TEST(ConvertStringToHexTest, strlenSmallerThanZeroOrEqualToZero){
	std::string inputString = "ABCDEF";
	int inputStringLength = -1;
	unsigned char output[3];
	unsigned char expectedOutput[3] = {0xAB, 0xCD, 0xEF};
	converter.convert_String_To_Hex(inputString.c_str(), inputStringLength, output);
	
	ASSERT_NE(expectedOutput[0], output[0]);
	ASSERT_NE(expectedOutput[1], output[1]);
	ASSERT_NE(expectedOutput[2], output[2]);

	inputStringLength = 0;
	converter.convert_String_To_Hex(inputString.c_str(), inputStringLength, output);

	ASSERT_NE(expectedOutput[0], output[0]);
	ASSERT_NE(expectedOutput[1], output[1]);
	ASSERT_NE(expectedOutput[2], output[2]);
}

//convert_Hex_to_String Unit tests
TEST(ConvertHexToString, Right_result) {
	unsigned char input[3] = {0xAB, 0xCD, 0xEF};
	int input_len = sizeof(input);
	std::string expectedOutput = "ABCDEF";
	std::string output = converter.convert_Hex_To_String(input, input_len);

	ASSERT_EQ(expectedOutput, output);
}

TEST(ConvertHexToString, Length_is_0){
	unsigned char input[3] = {0xAB, 0xCD, 0xEF};
	int input_len = 0;
	std::string expectedOutput = "";
	std::string output = converter.convert_Hex_To_String(input, input_len);

	ASSERT_EQ(expectedOutput, output);
}

TEST(ConvertHexToString, Length_is_Smaller_Than_0){
	unsigned char input[3] = {0xAB, 0xCD, 0xEF};
	int input_len = -999;
	std::string expectedOutput = "";
	std::string output = converter.convert_Hex_To_String(input, input_len);

	ASSERT_EQ(expectedOutput, output);
}