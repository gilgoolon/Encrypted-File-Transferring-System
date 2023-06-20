#include "Client.h"
#include <iostream>
#include "Utils.h"
#include "protocol.h"
#include "aes.h"

//std::string clientPath = "C:\\Users\\alper\\source\\repos\\mmn15_defensive_programming\\mmn15_defensive_programming\\me.info";
std::string clientPath = "me.info";

Client::Client(std::string& tp)
{
	port = "1234"; // default port number
	serverIP = "127.0.0.1"; // default server address
	transferPath = tp;
	fileHandler = new FileHandler();
	socketHandler = new SocketHandler();
}

Client::~Client()
{
	delete fileHandler, socketHandler;
}

bool Client::parseTransferInfo()
{
	if (!fileHandler->open(transferPath, false)) // read mode
	{
		printClientError("file handler failed opening the trasnfer file");
		return false;
	}

	std::cout << "Parsing transfer info..." << std::endl;
	
	std::string line1;

	if (!fileHandler->readLine(line1))
	{
		printClientError("file handler failed reading the first line of the transfer file");
		return false;
	}

	auto tok = line1.find(':');
	serverIP = line1.substr(0, tok); // server ip part
	line1.erase(0, tok + 1); // erase the ip part
	port = line1; // save the port as a string (boost accepts string)
	socketHandler->setSocket(serverIP, port);
	
	if (!fileHandler->readLine(cd.name)) // read second line into username
	{
		printClientError("file handler failed reading the second line of the transfer file");
		return false;
	}

	if (!fileHandler->readLine(filePath)) // read third line into filePath
	{
		printClientError("file handler failed reading the third line of the transfer file");
		return false;
	}

	fileHandler->close();
	
	if (!doesFileExist(filePath)) {
		printClientError("given file in transfer.info doesn't exist.");
		return false;
	}

	return true;
}

bool Client::parseClientInfo()
{
	if (!fileHandler->open(clientPath, false)) // read mode
	{
		printClientError("file handler failed opening the client file");
		return false;
	}

	if (!fileHandler->readLine(cd.name)) // reading client name
	{
		printClientError("file handler failed reading the first line of the client file");
		return false;
	}

	std::string hexCID;
	if (!fileHandler->readLine(hexCID)) // read client id
	{
		printClientError("file handler failed reading the second line of the client file");
		return false;
	}
	unhex(hexCID, cd.cid.cid);

	std::string base64PrivKey;
	if (!fileHandler->readLine(base64PrivKey)) // read client private key
	{
		printClientError("file handler failed reading the third line of the client file");
		return false;
	}

	fileHandler->close();
}

bool Client::storeClientInfo()
{
	if (!fileHandler->open(clientPath, true)) // write mode
	{
		printClientError("file handler failed opening the client file");
		return false;
	}

	if (!fileHandler->writeLine(cd.name)) // write name
	{
		printClientError("file handler failed writing to the client file");
		return false;
	}

	std::string hexID;
	hex(hexID, cd.cid.cid, sizeof(cd.cid.cid));
	if (!fileHandler->writeLine(hexID)) // write cid
	{
		printClientError("file handler failed writing to the client file");
		return false;
	}

	
	std::string key64 = Base64Wrapper::encode(rsaPrivateWrapper.getPrivateKey());
	if (!fileHandler->writeLine(key64)) // write Base64 encoded private key
	{
		printClientError("file handler failed writing to the client file");
		return false;
	}

	fileHandler->close();
	return true;
}

// send register request from client and save the allocated id
bool Client::registerClient()
{
	// register the client
	RegistrationRequest req;
	RegistrationResponse res;

	// fill req data
	req.header.payloadSize = sizeof(req.payload);
	strcpy_s(reinterpret_cast<char*>(req.payload.name.name), NAME_SIZE, cd.name.c_str());

	if (!socketHandler->sendAndReceive(reinterpret_cast<uint8_t*>(&req), sizeof(req),
		reinterpret_cast<uint8_t*>(&res), sizeof(res)))
	{
		printClientError("failed sending or recieving from server.");
		return false;
	}

	if (res.header.code != REGISTRATION_ACCEPTED) // failed registering
	{
		printServerError("server rejected registration");
		return false;
	}

	// res is now filled with the correct registration response, meaning we have a generated id
	memcpy(cd.cid.cid, res.payload.cid.cid, sizeof(cd.cid.cid)); // save the id given by the 
	return true;
}

bool Client::sendPublicKey()
{
	PublicKeyRequest req(cd.cid); // initialize the req with the id
	uint8_t* payload = nullptr;
	size_t payloadSize = 0;

	req.header.payloadSize = sizeof(req.payload);
	strcpy_s(reinterpret_cast<char*>(req.payload.name.name), NAME_SIZE, cd.name.c_str());
	rsaPrivateWrapper.getPublicKey(reinterpret_cast<char*>(req.payload.publicKey.publicKey), RSAPrivateWrapper::BITS);

	// send, receive unknown payload size and verify header protocol code
	if (!socketHandler->sendAndReceiveDynammic(reinterpret_cast<uint8_t*>(&req), sizeof(req), payload, payloadSize, PUBLIC_KEY_RECIEVED))
	{
		printClientError("couldn't send or recieve public key properly.");
		return false;
	}

	// 16 bytes of cid and encrypted AES key is now stored in res, since server responded
	// could check the cid here if we'd like to verify
	// decrease size left. payloadSize will be the length of the encrypted aes key
	std::string aesKey = rsaPrivateWrapper.decrypt(reinterpret_cast<char*>(payload+16), payloadSize-16);
	memcpy(cd.symmetricKey.symmetricKey, aesKey.c_str(), AESWrapper::DEFAULT_KEYLENGTH);

	delete[] payload; // free the heap memory allocated by the dynammic function
	return true;
}

int Client::reconnectClient()
{
	RegistrationRequest req; // reconnection and registration requests have the same format
	uint8_t* payload = nullptr;
	size_t payloadSize = 0;

	req.header.code = RECONNECT;

	req.header.payloadSize = sizeof(req.payload);
	strcpy_s(reinterpret_cast<char*>(req.payload.name.name), NAME_SIZE, cd.name.c_str());

	if (!fileHandler->open(clientPath, false))
	{
		printClientError("couldnt open me.info file");
		return 0;
	}

	std::string currLine;
	// skip first line - already have name from transfer file
	fileHandler->readLine(currLine);
	// read and copy cid
	fileHandler->readLine(currLine);
	unhex(currLine, cd.cid.cid);
	memcpy(req.header.cid.cid, cd.cid.cid, sizeof(cd.cid.cid));

	std::string privKey = "";
	std::string privKeyToPrint = "";
	// read 64 character lines
	while (fileHandler->readLine(currLine)) {
		privKey.append(currLine);
		privKeyToPrint.append(currLine).append("\n");
	}

	fileHandler->close();

	// if the file DOES exist, that means this client has already registered
	std::cout << "me.info exists. Reconnecting with details:" << std::endl
		<< "\tUsername: " << cd.name << std::endl
		<< "\tUser ID: ";
	for (int i = 0; i < sizeof(cd.cid.cid); i++)
		printf("%02X", cd.cid.cid[i]);
	std::cout << std::endl;
	std::stringstream ss(privKeyToPrint); // create a stringstream object from the text string

	std::string line;
	std::string title = "\tPrivate key: ";
	if (std::getline(ss, line))
		title.append(line);
	std::cout << title << std::endl; // print the title string
	
	while (std::getline(ss, line))
		std::cout << "\t             " << line << std::endl; // print each line with a fixed number of spaces before it

	std::cout << std::endl;

	// send, receive unknown payload size and verify header protocol code
	int status;
	if ((status = socketHandler->sendAndReceiveDynammic(reinterpret_cast<uint8_t*>(&req), sizeof(req), payload, payloadSize, RECONNECT_ACCEPTED)) == 0)
	{
		printClientError("couldn't send, receive or reconnect properly.");
		return 0;
	}
	
	// if reconnection failed by wrong code try again
	if (status == -1)
		return -1;
	// load the rsa private key from the me.info file
	

	RSAPrivateWrapper rsaPrivateWrapper2(Base64Wrapper::decode(privKey));

	// 16 bytes of cid and encrypted AES key is now stored in res, since server responded
	// could check the cid here if we'd like to verify
	// decrease size left. payloadSize will be the length of the encrypted aes key
	std::string aesKey = rsaPrivateWrapper2.decrypt(reinterpret_cast<char*>(payload + 16), payloadSize - 16);
	memcpy(cd.symmetricKey.symmetricKey, aesKey.c_str(), AESWrapper::DEFAULT_KEYLENGTH);

	delete[] payload; // free the heap memory allocated by the dynammic function
	return 1;
}

bool Client::sendFile()
{
	FileSendRequest req(cd.cid);
	FileSendResponse res;
	uint8_t* content = nullptr;

	if (!fileHandler->open(filePath, false)) // open the file to transfer in read mode
	{
		printClientError("couldn't open the file to transfer");
		return false;
	}
	
	AESWrapper aesWrapper(cd.symmetricKey.symmetricKey, AESWrapper::DEFAULT_KEYLENGTH);

	std::string encryptedFile = "";
	uint8_t buff[CryptoPP::AES::BLOCKSIZE]{ DEFAULT };
	size_t bytesRead;
	size_t plainFileSize = 0;
	uint8_t* plainFile = nullptr; // save the file in this format too for checksum later
	bool addedEOF = false;
	while ((bytesRead = fileHandler->readBytes(buff, CryptoPP::AES::BLOCKSIZE)) != -1)
	{
		if (bytesRead < CryptoPP::AES::BLOCKSIZE) {
			buff[bytesRead++] = 0x05; // EOF
			addedEOF = true;
		}
		encryptedFile.append(aesWrapper.encrypt(reinterpret_cast<char*>(buff), bytesRead));

		plainFileSize += bytesRead;
		uint8_t* ptr = (uint8_t*)malloc(plainFileSize);
		memcpy(ptr, plainFile, plainFileSize - bytesRead);
		memcpy(ptr + plainFileSize - bytesRead, buff, bytesRead);
		free(plainFile);
		plainFile = ptr;

		memset(buff, DEFAULT, CryptoPP::AES::BLOCKSIZE);
	}

	req.payload.contentSize = encryptedFile.size();
	memcpy(req.payload.filename.name, filePath.c_str(), filePath.size());
	content = new uint8_t[req.payload.contentSize];
	memcpy(content, encryptedFile.c_str(), req.payload.contentSize);

	size_t reqSize;
	uint8_t* reqToSend;
	req.header.payloadSize = sizeof(req.payload) + req.payload.contentSize;
	
	// prepare all data in one continuous array
	reqToSend = new uint8_t[sizeof(req) + req.payload.contentSize];
	memcpy(reqToSend, &req, sizeof(req));
	memcpy(reqToSend + sizeof(req), content, req.payload.contentSize);
	reqSize = sizeof(req) + req.payload.contentSize;

	std::cout << "Sending encrypted file " << filePath << " to server..." << std::endl << std::endl;

	if (!socketHandler->sendAndReceive(reqToSend, reqSize, reinterpret_cast<uint8_t*>(&res), sizeof(res)))
	{
		delete[] reqToSend;
		printClientError("failed to send or recieve file.");
		return false;
	}

	delete[] reqToSend;
	if (res.header.code != FILE_RECIEVED_CRC)
	{
		printServerError("server responded ith a wrong code.");
		return false;
	}

	// plainFileSize - 1 to disregard the EOF marker added previously
	csize_t actualChecksum = checksum(plainFile, plainFileSize - (addedEOF ? 1 : 0));
	// res is now filled with the checksum, confirm it
	if (actualChecksum != res.payload.checksum)
	{
		printServerError("server responded with wrong checksum: server " + std::to_string(res.payload.checksum) + " VS actual " + std::to_string(actualChecksum));
		return false;
	}
	free(plainFile);

	std::cout << "Server responded with correct checksum. Sending confirmation request..." << std::endl;

	return true;
}

bool Client::sendWrongCRCSending()
{
	RegistrationRequest req;
	memcpy(req.header.cid.cid, cd.cid.cid, sizeof(cd.cid.cid));
	req.header.code = CRC_WRONG_AGAIN;
	memcpy(req.payload.name.name, reinterpret_cast<uint8_t*>(const_cast<char*>(filePath.c_str())), NAME_SIZE);
	req.header.payloadSize = sizeof(req.payload);
	if (!socketHandler->connect())
	{
		printClientError("failed to connect to server");
		return false;
	}

	if (!socketHandler->send(reinterpret_cast<uint8_t*>(&req), sizeof(req)))
	{
		printClientError("failed sending wrong CRC message to server");
		return false;
	}

	return true;
}

bool Client::sendDoneSending()
{
	RegistrationRequest req;
	RegistrationResponse res;
	memcpy(req.header.cid.cid, cd.cid.cid, sizeof(cd.cid.cid));
	req.header.code = CRC_WRONG_DONE;
	req.header.payloadSize = sizeof(req.payload);
	memcpy(req.payload.name.name, reinterpret_cast<uint8_t*>(const_cast<char*>(filePath.c_str())), NAME_SIZE);

	if (!socketHandler->sendAndReceive(reinterpret_cast<uint8_t*>(&req), sizeof(req), reinterpret_cast<uint8_t*>(&res), sizeof(res)))
	{
		printClientError("failed sending or recieving done sending message");
		return false;
	}

	if (res.header.code != MESSAGE_RECIEVED)
	{
		printServerError("general error");
		return false;
	}
	return true;
}

bool Client::sendCRCGood()
{
	RegistrationRequest req;
	RegistrationResponse res;
	memcpy(req.header.cid.cid, cd.cid.cid, sizeof(cd.cid.cid));
	req.header.code = CRC_GOOD;
	req.header.payloadSize = sizeof(req.payload);
	strcpy_s(reinterpret_cast<char*>(req.payload.name.name), NAME_SIZE, filePath.c_str());

	if (!socketHandler->sendAndReceive(reinterpret_cast<uint8_t*>(&req), sizeof(req), reinterpret_cast<uint8_t*>(&res), sizeof(res)))
	{
		printClientError("failed sending or recieving good CRC message");
		return false;
	}

	if (res.header.code != MESSAGE_RECIEVED)
	{
		printServerError("general error");
		return false;
	}

	std::cout << "Message received by server. Terminating successfully." << std::endl;
	return true;
}

bool Client::start()
{
	std::cout << std::endl;
	std::cout << "Transfer information:" << std::endl;
	std::cout << "\tServer IP: " << serverIP << std::endl;
	std::cout << "\tPort: " << port << std::endl;
	std::cout << "\tUsername: " << cd.name << std::endl;
	std::cout << "\tFile to transfer: " << filePath << std::endl;
	std::cout << std::endl;

	bool connected = false;
	int status = 0;
	if (doesFileExist(clientPath))
	{
		status = connectByReconection();
		if (status == 0)
			return false;
		if (status == 1)
			connected = true;
	}

	if (!connected) {
		if (status == -1)
			std::cout << "Server denied reconnection, registering instead." << std::endl;
		else std::cout << "me.info doesn't exist, registering normally." << std::endl;
		if (!connectByRegistration())
			return false;
	}

	std::cout << "Client is now connected, AES key is: ";
	for (int i = 0; i < AESWrapper::DEFAULT_KEYLENGTH; i++)
		printf("%02X", cd.symmetricKey.symmetricKey[i]);
	std::cout << std::endl;

	// client is connected, obtained AES key already, can send an encrypted file now...
	// send an encrypted file (up to 3 times if checksum isn't right)
	for (int i = 0; i <= MAX_TRIES; i++) {
		if (i == MAX_TRIES) {
			printServerError("server failed to authenticate the file " + std::to_string(MAX_TRIES) + " times. Stopping.");
			sendDoneSending();
			return true; // not a client error...
		}
		if (sendFile())
			break;
		else
			sendWrongCRCSending();
	}

	if (!sendCRCGood())
	{
		printClientError("failed to send good CRC message to server");
		return false;
	}
	return true;
}

bool Client::connectByRegistration() {
	// if the me.info file does not exist, register the client,
	// create the me.info file, and save the id in it
	if (!registerClient())
		return false;


	fileHandler->open(clientPath, true); // open for writing

	// write the client name on the first line
	fileHandler->writeLine(cd.name);

	// prepare and write the client id in hexadecimal format on the second line
	std::string hexedID;
	hex(hexedID, cd.cid.cid, sizeof(cd.cid.cid));
	fileHandler->writeLine(hexedID);

	// prepare and write the private RSA key in base 64 format on the third line
	std::string b64privKey = Base64Wrapper::encode(rsaPrivateWrapper.getPrivateKey());
	fileHandler->writeLine(b64privKey);
	fileHandler->close();

	// now send the public key to the server and get the encrypted AES key as a response
	if (!sendPublicKey())
		return false;
	// if there has been an error, terminate. else, continue while merging with the reconection branch...
	return true;
}

int Client::connectByReconection() {
	// and should reconnect instead of registering again...
	return reconnectClient();
}

void Client::printClientError(std::string e)
{
	std::cout << "Error in client: " << e << std::endl;
}

void Client::printServerError(std::string e)
{
	std::cout << "Server responded with an error: " << e << std::endl;
}