#include "chat.h"
#include <hex.h>
#include <filters.h>
#include <C:/Users/dwarf/source/repos/Crypto_Lab3CRCPP/third-party/json.hpp>

using namespace CryptoPP;
using json = nlohmann::json;

AutoSeededRandomPool rng;

std::string EncodeBase64(const std::string& input) 
{
    std::string output;
    StringSource(input, true, new Base64Encoder(new StringSink(output)));
    return output;
}

std::string DecodeBase64(const std::string& input) 
{
    std::string output;
    StringSource(input, true, new Base64Decoder(new StringSink(output)));
    return output;
}

std::string ComputeHMAC(const std::string& message, const SecByteBlock& key) 
{
    std::string mac;
    HMAC<SHA256> hmac(key, key.size());
    StringSource(message, true, new HashFilter(hmac, new StringSink(mac)));
    return mac;
}

std::string EncryptAES(const std::string& plaintext, const SecByteBlock& key) 
{
    std::string ciphertext;
    SecByteBlock iv(AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size(), iv);
    StringSource(plaintext, true, new StreamTransformationFilter(encryption, new StringSink(ciphertext)));
    return EncodeBase64(std::string((char*)iv.data(), iv.size()) + ciphertext);
}

std::string DecryptAES(const std::string& ciphertextBase64, const SecByteBlock& key) 
{
    std::string ciphertext = DecodeBase64(ciphertextBase64);
    std::string plaintext;
    SecByteBlock iv((const byte*)ciphertext.data(), AES::BLOCKSIZE);
    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, key.size(), iv);
    StringSource(ciphertext.substr(AES::BLOCKSIZE), true, new StreamTransformationFilter(decryption, new StringSink(plaintext)));
    return plaintext;
}

std::string CreateMessage(const std::string& text, const SecByteBlock& key) 
{
    std::string encryptedText = EncryptAES(text, key);
    std::string mac = ComputeHMAC(encryptedText, key);
    json j;
    j["hash"] = EncodeBase64(mac);
    j["message"] = encryptedText;
    return j.dump();
}

bool VerifyMessage(const std::string& jsonMessage, const SecByteBlock& key, std::string& decryptedText) 
{
    json j = json::parse(jsonMessage);
    std::string receivedMac = DecodeBase64(j["hash"].get<std::string>());
    std::string encryptedText = j["message"].get<std::string>();
    std::string computedMac = ComputeHMAC(encryptedText, key);
    if (receivedMac != computedMac) {
        return false;
    }
    decryptedText = DecryptAES(encryptedText, key);
    return true;
}

SecByteBlock ConvertStringToSecByteBlock(const std::string& str) 
{
    SecByteBlock secByteBlock((const byte*)str.data(), str.size());
    return secByteBlock;
}

std::string generate128Key()
{
    int bits = 12;
    long long a, b, g, p;
    std::string key128 = "";

    for (int i = 0; i < 4; i++)
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(pow(2, bits - 1), pow(2, bits));

        a = dis(gen), b = dis(gen), g = dis(gen), p = dis(gen);

        long long key = generateDHK(g, p, a, b);
        if (key < 0)
            key *= -1;
        key128 += std::to_string(key);
    }

    if (key128.size() < 16)
        for (int i = 0; i < 16 - key128.size() + i; i++)
            key128 += "0";
    return key128;
}

long long generateDHK(long long g, long long p, long long a, long long b)
{
    long long A = fastModulePower(g, a, p);
    long long B = fastModulePower(g, b, p);

    long long K1 = fastModulePower(A, b, p);
    long long K2 = fastModulePower(B, a, p);

    if (K1 == K2)
        return K1;
}

long long int fastModulePower(int num, int pow, int module)
{
    int mask_size = log2(pow) + 1;
    int* mask = new int[mask_size];
    int* modules = new int[mask_size];
    long long int result = 1;

    FillTheMask(mask, pow, mask_size);

    modules[0] = num;
    for (int i = 1; i < mask_size; i++)
    {
        modules[i] = (modules[i - 1] * modules[i - 1]) % module;
    }

    for (int i = 0; i < mask_size; i++)
    {
        if (mask[i] == 1)
            result *= modules[i];
    }

    return result % module;
}

void FillTheMask(int* mask, int pow, int size)
{
    int check;
    double d = pow;
    for (int i = 0; i < size; i++)
    {
        check = 1;
        for (int j = 0; j < size; j++)
        {
            if (check > d / 2)
            {
                mask[j] = 1;
                d -= check;
                break;
            }
            check *= 2;
        }
    }
}