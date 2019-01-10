NAME=AES_Decryption
CC=g++
LIBS= -lssl -lcrypto
MAIN= Decryption_Files/main.cpp
TEST_MAIN= $(wildcard Tests/*.cpp)
SRCS= Decryption_Files/Converter.cpp Decryption_Files/AES.cpp

$(NAME):
	$(CC) $(MAIN) $(SRCS) $(LIBS) -o $(NAME)

clean:
	rm -rf $(NAME)

tests:
	$(CC) $(TEST_MAIN) $(SRCS) -lgtest -lgtest_main $(LIBS) -o RUN_TESTS
