#pragma once
#include <string>
void unhex(std::string& hex, uint8_t* dest);
void hex(std::string& dest, uint8_t* data, size_t size);
bool doesFileExist(std::string path);
uint32_t checksum(uint8_t* file, size_t size);