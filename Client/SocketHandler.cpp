#include "SocketHandler.h"
#include <boost/asio.hpp>
#include <iostream>

using boost::asio::ip::tcp;
using boost::asio::io_context;

SocketHandler::SocketHandler() : ioC(nullptr), resolver(nullptr), socket(nullptr), isConnected(false)
{
	union
	{
		uint32_t i;
		uint8_t c[sizeof(uint32_t)];
	} test{ 1 };
	isBigEndian = test.c[0] == 0;
}

SocketHandler::~SocketHandler()
{
	close();
}

bool SocketHandler::setSocket(std::string& a, std::string p)
{
	// could add validation to ip and port here
	address = a;
	port = p;

	return true;
}

bool SocketHandler::connect()
{
	try
	{
		if (isConnected)
			close();
		ioC = new io_context;
		resolver = new tcp::resolver(*ioC);
		socket = new tcp::socket(*ioC);
		boost::asio::connect(*socket, resolver->resolve(address, port, tcp::resolver::query::canonical_name));
		isConnected = true;
	}
	catch (...)
	{
		isConnected = false;
	}
	return isConnected;
}

void SocketHandler::close()
{
	if (!isConnected)
		return;
	
	delete socket, ioC, resolver;
	socket = nullptr;
	ioC = nullptr;
	resolver = nullptr;
	isConnected = false;
}

bool SocketHandler::receive(uint8_t* destination, size_t size)
{
	if (!isConnected || destination == nullptr || socket == nullptr)
		return false;

	size_t rem = size;
	uint8_t* ptr = destination;
	while (rem > 0)
	{
		uint8_t curr[BUFF_SIZE] = { 0 };
		boost::system::error_code errorCode;
		
		size_t curr_length = read(*socket, boost::asio::buffer(curr, BUFF_SIZE), errorCode);
		if (!curr_length) // while rem > 0 !!!
			return false;

		if (isBigEndian)
			swapBytes(curr, curr_length);

		size_t toCopy = curr_length < rem ? curr_length : rem;
		memcpy(ptr, curr, toCopy);
		ptr += toCopy;
		rem = rem < toCopy ? 0 : rem - toCopy; // so wont be -1 because unsigned
	}

	return true;
}

bool SocketHandler::send(uint8_t* source, size_t size)
{
	if (!isConnected || source == nullptr || socket == nullptr)
		return false;

	size_t rem = size;
	uint8_t* ptr = source;
	while (rem > 0)
	{
		uint8_t curr[BUFF_SIZE] = { 0 };
		size_t toSend = BUFF_SIZE < rem ? BUFF_SIZE : rem;

		boost::system::error_code errorCode;

		memcpy(curr, ptr, toSend);
		if (isBigEndian)
			swapBytes(curr, toSend);

		size_t sent = write(*socket, boost::asio::buffer(curr, toSend), errorCode);

		if (sent == 0) // while rem > 0 !!!
			return false;

		ptr += sent;
		rem = rem < sent ? 0 : rem - sent; // so wont be -1 because unsigned
	}

	return true;
}

bool SocketHandler::sendAndReceive(uint8_t* source, size_t sourceSize, uint8_t* dest, size_t destSize)
{
	if (!connect())
		return false;
	if (!send(source, sourceSize))
		return false;
	if (!receive(dest, destSize))
		return false;
	return true;
}

int SocketHandler::sendAndReceiveDynammic(uint8_t* req, size_t reqSize, uint8_t*& payload, size_t& payloadSize, ResponseCodes expectedCode) {
	ResponseHeader responseHeader;
	uint8_t buffer[BUFF_SIZE];
	payload = nullptr;
	payloadSize = 0;
	if (req == nullptr || reqSize == 0)
		return 0;

	if (!this->connect())
		return 0;

	if (!this->send(req, reqSize))
	{
		this->close();
		return 0;
	}

	if (!this->receive(buffer, sizeof(buffer)))
		return 0;

	// copy only the header part of the BUFF_SIZE bytes that were read into buffer
	memcpy(&responseHeader, buffer, sizeof(ResponseHeader));

	// validate that the code is the expected code, otherwise the expected payload fields will be messed up
	// in case of wrong protocol code
	if (responseHeader.code != expectedCode)
		return -1;
	
	// if the size of the payload is 0 (for example in an empty file) were done (with no error so return true)
	if (responseHeader.payloadSize == 0)
		return 1;

	payloadSize = responseHeader.payloadSize;
	payload = new uint8_t[payloadSize];
	uint8_t* ptr = static_cast<uint8_t*>(buffer) + sizeof(ResponseHeader);
	size_t recSize = sizeof(buffer) - sizeof(ResponseHeader);
	if (recSize > payloadSize)
		recSize = payloadSize;
	memcpy(payload, ptr, recSize);
	ptr = payload + recSize;
	while (recSize < payloadSize)
	{
		size_t toRead = (payloadSize - recSize);
		if (toRead > BUFF_SIZE)
			toRead = BUFF_SIZE;
		if (!this->receive(buffer, toRead))
		{
			delete[] payload;
			payload = nullptr;
			payloadSize = 0;
			return 0;
		}
		memcpy(ptr, buffer, toRead);
		recSize += toRead;
		ptr += toRead;
	}

	return 1;
}


void SocketHandler::swapBytes(uint8_t* buffer, size_t size)
{
	if (buffer == nullptr || size < sizeof(uint32_t))
		return;

	size -= (size % sizeof(uint32_t));
	uint32_t* const ptr = reinterpret_cast<uint32_t* const>(buffer);
	for (size_t i = 0; i < size; ++i)
	{
		const uint32_t tmp = ((buffer[i] << 8) & 0xFF00FF00) | ((buffer[i] >> 8) & 0xFF00FF);
		buffer[i] = (tmp << 16) | (tmp >> 16);
	}

}
