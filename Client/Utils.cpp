#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include "hex.h"
#include "base64.h"
#include "crc.h"
#include "cryptlib.h"

void unhex(std::string& hex, uint8_t* dest)
{
    std::vector<uint8_t> bytes = std::vector<uint8_t>(hex.length() / 2);
    for (int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes[i / 2] = byte;
    }
    memcpy(dest, bytes.data(), bytes.size());
}

void hex(std::string& dest, uint8_t* data, size_t size)
{
    std::vector<uint8_t> bytes(data, data + size);
    std::stringstream ss;
    for (int i = 0; i < bytes.size(); ++i) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)bytes[i];
    }
    dest = ss.str();
}

bool doesFileExist(std::string path)
{
    std::ifstream file(path);
    return file.good();
}

uint32_t checksum(uint8_t* file, size_t size)
{
    CryptoPP::CRC32 crc;
    crc.Update(file, size);

    uint32_t checksum;
    crc.Final((uint8_t*)&checksum);

    return checksum;
}