#pragma once
#include <ostream>
#include <boost/asio/ip/tcp.hpp>
#include "protocol.h"

using boost::asio::ip::tcp;
using boost::asio::io_context;

constexpr size_t BUFF_SIZE = 1024;

class SocketHandler
{
public:
	SocketHandler();
	~SocketHandler();

	// mark copy constructors for deletion:
	SocketHandler(const SocketHandler& other) = delete;
	SocketHandler(SocketHandler&& other) noexcept = delete;
	SocketHandler& operator=(const SocketHandler& other) = delete;
	SocketHandler& operator=(SocketHandler&& other) noexcept = delete;

	friend std::ostream& operator<<(std::ostream& os, const SocketHandler* sock) {
		if (sock != nullptr)
			os << sock->address << ':' << sock->port;
	}

	friend std::ostream& operator<<(std::ostream& os, SocketHandler& sock) {
		return os << &sock;
	}

	bool setSocket(std::string& address, std::string port);
	bool connect();
	void close();
	bool receive(uint8_t* dest, size_t size);
	bool send(uint8_t* source, size_t size);
	bool sendAndReceive(uint8_t* source, size_t, uint8_t* dest, size_t destSize);
	int sendAndReceiveDynammic(uint8_t*, size_t, uint8_t*&, size_t&, ResponseCodes);

private:
	std::string address;
	std::string port;
	io_context* ioC;
	tcp::resolver* resolver;
	tcp::socket* socket;
	bool isBigEndian;
	bool isConnected;

	void swapBytes(uint8_t* bytes, size_t size);
};

