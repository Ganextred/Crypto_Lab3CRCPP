#include <iostream>
#include "chat.h"

CryptoPP::AutoSeededRandomPool rng1;

int main() {
    std::string sharedKey = generate128Key();

    std::cout << "Diffie-Hellman Key: " << sharedKey << std::endl << "size = " << sharedKey.size() << std::endl;

    CryptoPP::SecByteBlock sharedKeySBB = ConvertStringToSecByteBlock(sharedKey);

    std::string message = "Short test message";
    std::string jsonMessage = CreateMessage(message, sharedKeySBB);

    std::cout << "JSON Message: " << jsonMessage << std::endl;

    std::string decryptedText;
    if (VerifyMessage(jsonMessage, sharedKeySBB, decryptedText)) {
        std::cout << "Decrypted Text: " << decryptedText << std::endl;
    }
    else {
        std::cout << "Failed to verify or decrypt the message." << std::endl;
    }

    return 0;
}
