#pragma once

#include <cryptlib.h>
#include <string>
#include <secblock.h>
#include <sha.h>
#include <aes.h>
#include <modes.h>
#include <hmac.h>
#include <base64.h>
#include <osrng.h>
#include <cmath>
#include <vector>
#include <random>
#include <ctime>

std::string EncodeBase64(const std::string& input);
std::string DecodeBase64(const std::string& input);
std::string ComputeHMAC(const std::string& message, const CryptoPP::SecByteBlock& key);
std::string EncryptAES(const std::string& plaintext, const CryptoPP::SecByteBlock& key);
std::string DecryptAES(const std::string& ciphertextBase64, const CryptoPP::SecByteBlock& key);
std::string CreateMessage(const std::string& text, const CryptoPP::SecByteBlock& key);
bool VerifyMessage(const std::string& jsonMessage, const CryptoPP::SecByteBlock& key, std::string& decryptedText);
CryptoPP::SecByteBlock ConvertStringToSecByteBlock(const std::string& str);
std::string generate128Key();
long long generateDHK(long long g, long long p, long long a, long long b);
long long int fastModulePower(int num, int pow, int module);
void FillTheMask(int* mask, int pow, int size);