#include "../Decryption_Files/AES.h"
#include <gtest/gtest.h>

AES decryptor;

std::string TAM1Key = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
std::string TAM2Key = "11111111111111111111111111111111";

//Test TAM 1 Authentication
TEST(TAM1DecryptTest, AuthenticateCorrectly){
	std::string iChallenge = "E4D3000B55C8C30508FD";
	std::string encryptedText = "4EDE50BD72F0AEACB532D1677DEB2908";

	bool authenticated = decryptor.DecryptTAM1(encryptedText, TAM1Key, iChallenge);

	ASSERT_TRUE(authenticated);
}

TEST(TAM1DecryptTest, EncryptedTextIncorrect){
	//encryptedText will be different
	std::string iChallenge = "E4D3000B55C8C30508FD";
	std::string encryptedText = "11223344556677889900AABBCCDDEEFF";

	bool authenticated = decryptor.DecryptTAM1(encryptedText, TAM1Key, iChallenge);

	ASSERT_FALSE(authenticated);
}

TEST(TAM1DecryptTest, KeyIncorrect) {
	std::string iChallenge = "E4D3000B55C8C30508FD";
	std::string encryptedText = "4EDE50BD72F0AEACB532D1677DEB2908";

	std::string wrongKey = "00112233445566778899AABBCCDDEEFF";

	bool authenticated = decryptor.DecryptTAM1(encryptedText, wrongKey, iChallenge);

	ASSERT_FALSE(authenticated);
}

TEST(TAM1DecryptTest, iChallengeIncorrect) {
	std::string iChallenge = "FFFF1111222233334444";
	std::string encryptedText = "4EDE50BD72F0AEACB532D1677DEB2908";

	bool authenticated = decryptor.DecryptTAM1(encryptedText, TAM1Key, iChallenge);

	ASSERT_FALSE(authenticated);
}

TEST(TAM1DecryptTest, EncryptedTextTooShort) {
	std::string iChallenge = "E4D3000B55C8C30508FD";
	std::string encryptedText = "4EDE50BD72F0AEA";

	bool authenticated = decryptor.DecryptTAM1(encryptedText, TAM1Key, iChallenge);

	ASSERT_FALSE(authenticated);
}

//Test TAM2 Decryption
// two of the epcs are the same for ease of testing
std::string EPCs[3] = {"000000313730333031393638", "E2C068920000003A1E2086E6", "E2C068920000003A1E2086E6"};

TEST(TAM2DecryptTest, CorrectEPCDecryption) {
	std::string iChallenges[3] = {"BDF5340CAC92052B038B", "16F6780F0D7EFE1CB0E8", "4EE48108EB8F8500609C"};

	std::string encryptedTexts[3] = {	"141585F836BC9D8EAA8F421D34DB902644EBB5B4F917871E060F7848846CD0E3", 
										"B609B998DD8A5265E6345EF7B152E688EA1AE5318E27EFFB94F34ECD9C61A606",
										"4A723C37711F8EFA6AF89C17689E265E03A9D747278ACB2942EAD03BE24B564C"};

	for (int i = 0; i < sizeof(iChallenges)/sizeof(iChallenges[0]); ++i)
	{
		std::string decryptedEPC = decryptor.DecryptTAM2(encryptedTexts[i], TAM2Key, iChallenges[i], 128);
		ASSERT_TRUE(decryptedEPC.find(EPCs[i]) != std::string::npos);
	}
}

TEST(TAM2DecryptTest, IncorrectEPCDecryption) {
	std::string iChallenges[3] = {"BDF5340CAC92052B038B", "16F6780F0D7EFE1CB0E8", "4EE48108EB8F8500609C"};

	//The last part of the ecryptedtexts will be different than the original response to trigger a fail
	std::string encryptedTexts[3] = {	"141585F836BC9D8EAA8F421D34DB902644EBB5B4F917871E060EEEEEEEEEEEEE", 
										"B609B998DD8A5265E6345EF7B152E688EA1AE5318E27EFFB94FFFFFFFFFFFFFF",
										"4A723C37711F8EFA6AF89C17689E265E03A9D747278ACB294211111111111111"};

	for (int i = 0; i < sizeof(iChallenges)/sizeof(iChallenges[0]); ++i)
	{
		std::string decryptedEPC = decryptor.DecryptTAM2(encryptedTexts[i], TAM2Key, iChallenges[i], 128);
		ASSERT_FALSE(decryptedEPC.find(EPCs[i]) != std::string::npos);
	}
}

//encryptedtext has to be 64 bytes long
TEST(TAM2DecryptTest, IncorrectEncryptedTextSize) {
	std::string iChallenges[3] = {"BDF5340CAC92052B038B", "16F6780F0D7EFE1CB0E8", "4EE48108EB8F8500609C"};

	std::string encryptedTexts[3] = {	"141585F836BC9D8EAA8F421D34DB902644E", 
										"B609B998DD8A5265E6345EF7B152E688EA1AE5318E27EFFB94FFFF",
										"4A723C37711F8EFA6AF89C17689E265E03A9D747278ACB294211111111111111444444444444444"};

	for (int i = 0; i < sizeof(iChallenges)/sizeof(iChallenges[0]); ++i)
	{
		std::string decryptedEPC = decryptor.DecryptTAM2(encryptedTexts[i], TAM2Key, iChallenges[i], 128);
		ASSERT_EQ("", decryptedEPC);
	}
}

// ichallenge has to be 20 chars long
TEST(TAM2DecryptTest, IncorrectIChallengeSize) {
	std::string iChallenges[3] = {"BDF5", "16F6780F0D7EFE1CB0", "4EE48108EB8F8500609CFFEEEDDD"};

	std::string encryptedTexts[3] = {	"141585F836BC9D8EAA8F421D34DB902644EBB5B4F917871E060F7848846CD0E3", 
										"B609B998DD8A5265E6345EF7B152E688EA1AE5318E27EFFB94F34ECD9C61A606",
										"4A723C37711F8EFA6AF89C17689E265E03A9D747278ACB2942EAD03BE24B564C"};

	for (int i = 0; i < sizeof(iChallenges)/sizeof(iChallenges[0]); ++i)
	{
		std::string decryptedEPC = decryptor.DecryptTAM2(encryptedTexts[i], TAM2Key, iChallenges[i], 128);
		ASSERT_EQ("", decryptedEPC);
	}
}

TEST(TAM2DecryptTest, CorrectTIDDecryption) {
	std::string TID = "E2C0689220006D021E2086E6";
	std::string iChallenges[2] = {"559F9C37A4C1501CDB38", "E68761229DE986050888"};

	std::string encryptedTexts[2] = {	"03A67C6FAF6B64A6A37D0E4982ECA326707EC488F5DAC0471D4532A42BE4D5BE", 
										"2F10B27963869E6DCE8C92075E1F719338919FEC4A5CFE9E51860EEEB0120D72"};

	for (int i = 0; i < sizeof(iChallenges)/sizeof(iChallenges[0]); ++i)
	{
		std::string decryptedTID = decryptor.DecryptTAM2(encryptedTexts[i], TAM2Key, iChallenges[i], 128);
		ASSERT_TRUE(decryptedTID.find(TID) != std::string::npos);
	}
}

TEST(TAM1DecryptTest, CorrectUserDataDecryption) {
	std::string userData = "6B7574";
	//user data is very long, this is more clean
	for (int i = 0; i < 762; ++i)
	{
		userData += '0';
	}

	std::string iChallenges[2] = {"7AD68D375D1322080089", "21506539DA3C932103AA"};

	std::string encryptedTexts[2] = {	"12C902B97A9ABCFF4EA9C809275A0A234919DCAFDAF2C4636E7D8B430FA6C390", 
										"5486AB4AF25A324557C59A5D1FD89B9020326525C7F29E660C57CD150F0FF693"};

	for (int i = 0; i < sizeof(iChallenges)/sizeof(iChallenges[0]); ++i)
	{
		std::string decryptedUserData = decryptor.DecryptTAM2(encryptedTexts[i], TAM2Key, iChallenges[i], 8000);
		ASSERT_TRUE(decryptedUserData.find(userData) != std::string::npos);
	}
}