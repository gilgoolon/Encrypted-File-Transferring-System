#include "FileHandler.h"
#include <string>

FileHandler::FileHandler()
{
	_isOpen = false;
	_fstream = nullptr;
	_isAtEnd = false;
}

FileHandler::~FileHandler()
{
	close();
}

bool FileHandler::open(const std::string& path, bool isWriteMode)
{
	const auto flag = isWriteMode ? std::fstream::out : std::fstream::in;
	if (path.empty())
		return false;

	try
	{
		close();
		_fstream = new std::fstream;
		_fstream->open(path, flag);
		_isOpen = _fstream->is_open();
		_isAtEnd = false;
	}
	catch (...)
	{
		_isOpen = false;
	}
	return _isOpen;
}

void FileHandler::close()
{
	if (!_isOpen)
		return;
	try
	{
		_fstream->close();
	}
	catch (...) {}
	_isOpen = _fstream->is_open();
	delete _fstream;
	_fstream = nullptr;
}

size_t FileHandler::readBytes(uint8_t* dest, size_t bytes)
{
	if (_fstream == nullptr || !_isOpen || dest == nullptr || bytes == 0 || _isAtEnd)
		return -1;

	try
	{
		_fstream->read(reinterpret_cast<char*>(dest), bytes);
		_isAtEnd = _fstream->tellg() == -1;
		return _fstream->gcount();
	}
	catch (...)
	{
		return -1;
	}
}

bool FileHandler::writeBytes(const uint8_t* source, size_t bytes)
{
	if (_fstream == nullptr || !_isOpen || source == nullptr || bytes == 0)
		return false;

	try
	{
		_fstream->write(reinterpret_cast<const char*>(source), bytes);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

// write a line to the file that is represented as a string refference 
bool FileHandler::writeLine(std::string& source)
{
	std::string s = source;
	s.append("\n");
	return writeBytes(reinterpret_cast<const uint8_t*>(s.c_str()), s.length());
}

bool FileHandler::readLine(std::string& dest)
{
	if (!_isOpen || _fstream == nullptr)
		return false;

	try
	{
		return std::getline(*_fstream, dest) && !dest.empty();
	}
	catch (...)
	{
		return false;
	}
}