#pragma once
#include <cstdint>

// type matching names: typedefs
typedef uint16_t version_t; // struct needs to be aligned. Can't use a single byte
typedef uint16_t code_t;
typedef uint32_t csize_t;

// constants - sizes in bytes
constexpr version_t VERSION = 3;
constexpr size_t ID_SIZE = 16;
constexpr size_t NAME_SIZE = 255;
constexpr size_t PUBLIC_KEY_SIZE = 160;
constexpr size_t SYMMETRIC_KEY_SIZE = 16;
constexpr size_t REQS = 7;
constexpr size_t RESS = 8;

constexpr uint8_t DEFAULT = 0;

enum RequestCodes
{
	REGISTRATION = 1100,
	PUBLIC_KEY = 1101,
	RECONNECT = 1102,
	FILE_SEND = 1103,
	CRC_GOOD = 1104,
	CRC_WRONG_AGAIN = 1105,
	CRC_WRONG_DONE = 1106
};

enum ResponseCodes
{
	REGISTRATION_ACCEPTED = 2100,
	REGISTRATION_DENIED = 2101,
	PUBLIC_KEY_RECIEVED = 2102,
	FILE_RECIEVED_CRC = 2103,
	MESSAGE_RECIEVED = 2104,
	RECONNECT_ACCEPTED = 2105,
	RECONNECT_REJECTED = 2106,
	GENERAL_ERROR = 2107
};

struct ClientID
{
	uint8_t cid[ID_SIZE];
	ClientID() : cid{ DEFAULT } {}

	// so we could compare client ids easily
	bool operator==(const ClientID& c)
	{
		for (size_t i = 0; i < ID_SIZE; i++)
			if (cid[i] != c.cid[i])
				return false;
		return true;
	}

	bool operator!=(const ClientID& c)
	{
		return !(*this == c);
	}
};

struct Name
{
	uint8_t name[NAME_SIZE];
	Name() : name{ DEFAULT } {}
};

struct PublicKey
{
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	PublicKey() : publicKey{ DEFAULT } {}
};

struct SymmetricKey
{
	uint8_t symmetricKey[SYMMETRIC_KEY_SIZE];
	SymmetricKey() : symmetricKey{ DEFAULT } {}
};

struct RequestHeader
{
	ClientID cid;
	version_t version;
	code_t code;
	csize_t payloadSize;
	RequestHeader(code_t code) : version(VERSION), code(code), payloadSize(DEFAULT) {}
	RequestHeader(ClientID& uuid, code_t code) : version(VERSION), code(code), cid(uuid), payloadSize(DEFAULT) {}
};

struct ResponseHeader
{
	version_t version;
	code_t code;
	csize_t payloadSize;
	ResponseHeader() : version(DEFAULT), code(DEFAULT), payloadSize(DEFAULT) {}
};

struct RegistrationRequest
{
	RequestHeader header;
	struct {
		Name name;
	} payload;
	RegistrationRequest() : header(REGISTRATION) {}
};

struct RegistrationResponse
{
	ResponseHeader header;
	struct {
		ClientID cid;
	} payload;
};

struct PublicKeyRequest
{
	RequestHeader header;
	struct {
		Name name;
		PublicKey publicKey;
	} payload;
	PublicKeyRequest(ClientID& id) : header(id, PUBLIC_KEY) {}
};

struct PublicKeyResponse
{
	ResponseHeader header;
	struct {
		ClientID cid;
		SymmetricKey symmetricKey;
	} payload;
};

struct FileSendRequest
{
	RequestHeader header;
	struct PayHeader {
		csize_t contentSize;
		Name filename;
		PayHeader() : contentSize(DEFAULT) {}
	} payload;
	FileSendRequest(ClientID& id) : header(id, FILE_SEND) {}
};

struct FileSendResponse
{
	ResponseHeader header;
	struct PayHeader {
		ClientID cid;
		csize_t contentSize;
		Name filename;
		csize_t checksum;
		PayHeader() : contentSize(DEFAULT), checksum(DEFAULT) {}
	} payload;
};