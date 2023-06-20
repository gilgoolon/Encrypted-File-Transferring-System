#pragma once
#include <fstream>

class FileHandler
{
private:
	bool _isOpen;
	bool _isAtEnd;
	std::fstream* _fstream;
	
public:
	FileHandler();
	~FileHandler();
	bool open(const std::string& path, bool isWriteMode);
	void close();
	size_t readBytes(uint8_t* dest, const size_t bytes);
	bool writeBytes(const uint8_t* source, const size_t bytes);
	bool writeLine(std::string& source);
	bool readLine(std::string& dest);
};

