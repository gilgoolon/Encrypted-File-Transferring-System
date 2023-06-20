from random import Random  # for key generation
import os  # for file management
import binascii  # for checksum calculation only
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP

AES_KEY_SIZE = 128 // 8
AES_IV = bytes([0] * AES.block_size)
DEFAULT_PORT = 1234
BASE_BACKUP_PATH = 'backups\\'


# parse the port number from a file containing a single line
def read_port_from_file(filename: str) -> int:
    try:
        with open(filename) as f:
            port = int(f.readline())
            if port <= 1024 or port >= 65536:
                return DEFAULT_PORT
            else:
                return port
    except FileNotFoundError:
        return DEFAULT_PORT


# check if a file exists in the system
def is_file_exists(filename: str) -> bool:
    try:
        f = open(filename)
        f.close()
        return True
    except FileNotFoundError:
        return False


# check if a given name is valid
def is_name_valid(name: str) -> bool:
    return name.replace(' ', '').isalnum()


def is_name_exists(clients: list[tuple], name: str) -> bool:
    for client in clients:
        if client[1] == name:
            return True
    return False


def gen_new_uuid(clients: list[tuple]) -> bytes:
    while True:
        uuid = Random().randbytes(16)
        if any(uuid == client[0] for client in clients):
            continue
        return uuid


def is_id_exists(clients: list[tuple], uuid: bytes) -> bool:
    for client in clients:
        if client[0] == uuid:
            return True
    return False


def is_public_key_exists(clients: list[tuple], client: bytes) -> bool:
    for c in clients:
        if c[0] == client:
            return client[2] is not None
    return False


def set_aes_key_for_client(clients: list[tuple], uuid: bytes, key: bytes) -> None:
    for i in range(len(clients)):
        if clients[i][0] == uuid:
            clients[i] = (uuid, clients[i][1], clients[i][2], key)
            return


def set_public_key_for_client(clients: list[tuple], uuid: bytes, public_key: bytes) -> bool:
    for i in range(len(clients)):
        print(clients)
        if clients[i][0] == uuid:
            clients[i] = (uuid, clients[i][1], public_key, clients[i][3])
            return True
    return False


def get_aes_key(clients: list[tuple], uuid: bytes) -> bytes:
    for client in clients:
        if client[0] == uuid:
            return client[3]
    return b''


# generate an AES key
def gen_aes_key():
    return Random().randbytes(AES_KEY_SIZE)


# encrypt bytes using the given public key and RSA encryption
def encrypt_public(text: bytes, public_key: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(text)


# decrypt encrypted bytes that were encrypted using the given key with AES encryption
def decrypt_symmetric(text: bytes, key: bytes) -> bytes:
    ans = b""
    for i in range(0, len(text), 2*AES.block_size):
        cipher = AES.new(key, AES.MODE_CBC, iv=AES_IV)
        ans += cipher.decrypt(text[i:i + AES.block_size])
    return ans.partition(b'\x05')[0]  # remove padding


# calculate the CRC checksum of a file, given its contents
def checksum(file: bytes) -> int:
    return binascii.crc32(file)


# save the given file on the server and return path saved to
def save_file(client: bytes, filename: str, file: bytes) -> str:
    path = BASE_BACKUP_PATH + str(client.hex()) + '\\' + filename
    os.makedirs(BASE_BACKUP_PATH + str(client.hex()), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(file)
    return path


# output the error and stop the server
def fatal_error(desc: str) -> None:
    print(f"Fatal error: {desc}.\nStopping the server immediately.")
    exit(1)
