#pragma once
#include <string>
#include "RSAWrapper.h"
#include "FileHandler.h"
#include "SocketHandler.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include <iomanip>

class Client
{
public:
	const static int MAX_TRIES = 3;
	struct ClientDetails
	{
		ClientID cid;
		std::string name;
		SymmetricKey symmetricKey;
	};


	Client(std::string& transferPath);
	~Client();

	// mark copy constructors for deletion
	Client(const Client& other) = delete;
	Client(Client&& other) noexcept = delete;
	Client& operator=(const Client& other) = delete;
	Client& operator=(Client&& other) noexcept = delete;

	bool parseTransferInfo();
	bool parseClientInfo();
	bool storeClientInfo();

	// requests functions
	bool registerClient();
	bool sendPublicKey();
	int reconnectClient();
	bool sendFile();
	bool sendWrongCRCSending();
	bool sendDoneSending();
	bool sendCRCGood();

	bool connectByRegistration();
	int connectByReconection();
	bool start();

private:
	std::string serverIP;
	std::string port;
	std::string transferPath;
	std::string filePath;

	ClientDetails cd;
	SocketHandler* socketHandler;
	FileHandler* fileHandler;
	RSAPrivateWrapper rsaPrivateWrapper;

	void printClientError(std::string e);
	void printServerError(std::string e);
};
