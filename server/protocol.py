import struct
from enum import Enum

SERVER_VERSION = 3
DEFAULT = 0
HEADER_SIZE = 2 + 2 + 4
ID_SIZE = 16
NAME_SIZE = 255
PUB_KEY_SIZE = 160
FILENAME_SIZE = 255
AES_KEY_SIZE = 128
COUNT_SIZE = 4


class RequestCodes(Enum):
    REGISTER = 1100
    PUBLIC_KEY = 1101
    RECONNECT = 1102
    FILE_SEND = 1103
    CRC_GOOD = 1104
    CRC_WRONG_AGAIN = 1105
    CRC_WRONG_DONE = 1106


class ResponseCodes(Enum):
    REGISTER_SUCCEEDED = 2100
    REGISTER_FAILED = 2101
    PUBLIC_KEY_RECEIVED = 2102
    FILE_RECEIVED_CRC = 2103
    MESSAGE_RECEIVED = 2104
    RECONNECT_ACCEPTED = 2105
    RECONNECT_FAILED = 2106
    GENERAL_ERROR = 2107


# Header format is:
# ClientID (16 bytes)
# Version (1 byte)
# Code (2 bytes)
# Payload Size (4 bytes)
#
# This class will need the unpacking option only since it will be packed by the client in c++ and unpacked here
class RequestHeader:
    def __init__(self):
        self.cid = b''
        self.version = DEFAULT
        self.code = DEFAULT
        self.payload_size = DEFAULT
        self.SIZE = HEADER_SIZE + ID_SIZE

    # unpack bytes data into a class and field for easy use, little endian
    # returns True if the format was ok, False otherwise
    def unpack(self, data: bytes) -> bool:
        try:
            # the packing and unpacking will be done in the format of little endian, which the '<' specifies,
            # and "BHL" means that the unpacking is of byte short long
            #                                            _    __  ____
            # or simply, 1 byte value, 2 byte value, and then a 4 byte value (all unsigned because uppercase)
            self.cid = struct.unpack(f"<{ID_SIZE}s", data[:ID_SIZE])[0]  # s for c chars, bytes in python
            self.version, self.code, self.payload_size = struct.unpack("<HHL", data[ID_SIZE:ID_SIZE + HEADER_SIZE])
            return True
        except:  # noqa: Too broad exception clause
            self.__init__()
            return False


# Header format is:
# Version (1 byte)
# Code (2 bytes)
# Payload Size (4 bytes)
#
# This class will need the packing option only since it will be decoded by the client in c++
# This header will also be used as failure responses which contain no payload
class ResponseHeader:
    def __init__(self, code=DEFAULT):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = DEFAULT
        self.SIZE = HEADER_SIZE

    def pack(self) -> bytes:
        try:
            # the packing and unpacking will be done in the format of little endian, which the '<' specifies,
            # and "BHL" means that the unpacking is of byte short long
            #                                            _    __  ____
            # or simply, 1 byte value, 2 byte value, and then a 4 byte value (all unsigned because uppercase)
            data = struct.pack("<HHL", self.version, self.code, self.payload_size)
            return data
        except:  # noqa: Too broad exception clause
            self.__init__()
            return b''


# Format:
# Request Header
# Name (255 bytes)
#
# Will be used as a reconnection request too
class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b''

    def unpack(self, data):

        if not self.header.unpack(data):
            return False
        try:
            name_unpacked = struct.unpack(f"<{NAME_SIZE + 1}s", data[self.header.SIZE:])[0]
            self.name = str(name_unpacked.partition(b'\0')[0].decode("utf-8"))
            return True
        except Exception as e:  # noqa: Too broad exception clause
            self.name = b''
            return False


# Format:
# Response Header
# UUID (16 bytes)
#
# Will be used as a response for a failed reconnect request and message received (2104) too
class RegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader()
        self.cid = b''

    def pack(self) -> bytes:
        try:
            return self.header.pack() + \
                   struct.pack(f"<{ID_SIZE}s", self.cid)
        except:  # noqa: Too broad exception clause
            return b''


# Format:
# Request Header
# Name (255 bytes max)
# Public Key (160 bytes)
class PublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b''
        self.public_key = b''

    def unpack(self, data: bytes) -> bool:
        if not self.header.unpack(data):
            return False

        name_unpacked = struct.unpack(f"<{NAME_SIZE}s", data[self.header.SIZE:self.header.SIZE + NAME_SIZE])[0]
        self.name = str(name_unpacked.partition(b'\0')[0].decode("utf-8"))
        self.public_key = struct.unpack(f">{PUB_KEY_SIZE}s", data[self.header.SIZE + NAME_SIZE:-1])[0]
        return True


# Format:
# Response Header
# Client ID (16 bytes)
# encrypted AES Key (dynamic since encrypted)
#
# Will be used as a response for a reconnection response too
class PublicKeyResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCodes.PUBLIC_KEY_RECEIVED.value)
        self.cid = b''
        self.aes_key = b''

    def pack(self) -> bytes:
        try:
            key_size = self.header.payload_size - ID_SIZE
            return self.header.pack() + \
                   struct.pack(f"<{ID_SIZE}s", self.cid) + \
                   struct.pack(f"<{key_size}s", self.aes_key)
        except:  # noqa: Too broad exception clause
            return b''


# Format:
# Request Header
# Content Size (4 bytes)
# File Name (255 bytes)
# File Content (dynamic)
class FileSendRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.content_size = DEFAULT
        self.filename = b''
        self.file_content = b''

    def unpack(self, data: bytes) -> bool:
        if not self.header.unpack(data):
            return False

        try:
            self.content_size = struct.unpack("<L", data[self.header.SIZE: self.header.SIZE + 4])[0]
            self.filename = struct.unpack(f"<{FILENAME_SIZE}s",
                                          data[self.header.SIZE + 4: self.header.SIZE + 4 + FILENAME_SIZE])[0]
            self.file_content = \
                struct.unpack(f"<{self.content_size}s", data[self.header.SIZE + 4 + FILENAME_SIZE + 1:])[0]
            return True
        except:  # noqa: Too broad exception clause
            self.content_size = DEFAULT
            self.filename = b''
            self.file_content = b''
            return False


# Format:
# Client ID (16 bytes)
# Content Size (4 bytes)
# Filename (255 bytes)
# Checksum (4 bytes)
class FileSendResponse:
    def __init__(self):
        self.header = ResponseHeader(code=ResponseCodes.FILE_RECEIVED_CRC.value)
        self.cid = b''
        self.content_size = DEFAULT
        self.filename = b''
        self.checksum = b''

    def pack(self) -> bytes:
        try:
            return self.header.pack() + \
                   struct.pack(f"<{ID_SIZE}s", self.cid) + \
                   struct.pack(f"<L", self.content_size) + \
                   struct.pack(f"<{FILENAME_SIZE + 1}s", self.filename + b'\x00') + \
                   struct.pack(f"<L", self.checksum)
        except:  # noqa: Too broad exception clause
            return b''


class CRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.filename = b''

    def unpack(self, data: bytes) -> bool:
        if not self.header.unpack(data):
            return False
        try:
            name_unpacked = struct.unpack(f"<{NAME_SIZE + 1}s", data[self.header.SIZE:])[0]
            self.filename = str(name_unpacked.partition(b'\0')[0].decode("utf-8"))
            return True
        except Exception as e:  # noqa: Too broad exception clause
            self.filename = b''
            return False
