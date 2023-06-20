import selectors
import socket

import database
import protocol
import utils


class Server:
    DB_FILENAME = 'server.db'
    BUFF_SIZE = 1024

    # constructor for Server object
    def __init__(self, port):
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.db = database.Database(self.DB_FILENAME)
        self.handle_reqs = {
            protocol.RequestCodes.REGISTER.value: self.handle_register_request,
            protocol.RequestCodes.RECONNECT.value: self.handle_reconnect_request,
            protocol.RequestCodes.PUBLIC_KEY.value: self.handle_public_key_request,
            protocol.RequestCodes.FILE_SEND.value: self.handle_file_send_request,
            protocol.RequestCodes.CRC_GOOD.value: self.handle_crc_good_request,
            protocol.RequestCodes.CRC_WRONG_AGAIN.value: self.handle_crc_wrong_again_request,
            protocol.RequestCodes.CRC_WRONG_DONE.value: self.handle_crc_wrong_done_request
        }
        self.clients = self.db.get_clients_list()

    # start the server: db initialization if needed and main loop
    def start(self):
        if not database.is_file_exists(self.DB_FILENAME):
            self.db.create_tables()
        try:
            s = socket.socket(socket.AF_INET)
            s.bind(('', self.port))
            s.listen()
            self.sel.register(s, selectors.EVENT_READ, self.accept)
        except Exception as e:  # noqa: Too broad exception clause
            return e
        print(f"Server started and is now listening on port {self.port}...")
        while True:
            try:
                for key, mask in self.sel.select():
                    key.data(key.fileobj, mask)
            except Exception as e:  # noqa: Too broad exception clause
                print(f"Error in server main loop: {e}.")
                break

    # accept a connection from a client and register in the selector
    def accept(self, sock: socket.socket, mask):
        con, address = sock.accept()  # don't care about the ip
        self.sel.register(con, selectors.EVENT_READ, self.read)

    # read data coming in from a client
    def read(self, con: socket.socket, mask):
        data = self.read_request(con)
        if data:
            header = protocol.RequestHeader()
            success = False
            # could check for error here
            if header.unpack(data):
                success = True
                if header.code in self.handle_reqs.keys():
                    self.handle_reqs[header.code](con, data)
                else:
                    # mark as unsuccessful
                    success = False
            if not success:
                # send a general error response
                self.send_general_error_message(con)
            self.db.update_LastSeen(header.cid)
        self.sel.unregister(con)
        con.close()

    # read a request using the payload size field
    def read_request(self, con: socket.socket) -> bytes:
        data = con.recv(self.BUFF_SIZE)
        header = protocol.RequestHeader()
        header.unpack(data)
        to_read = protocol.HEADER_SIZE + protocol.ID_SIZE + header.payload_size - self.BUFF_SIZE
        while to_read > 0:
            read_curr = min(to_read, self.BUFF_SIZE)
            data += con.recv(read_curr)
            to_read -= read_curr
        return data

    # send a response of 'data' to socket 'con' client
    def write(self, con: socket.socket, data: bytes) -> bool:  # noqa: function could be static
        size = len(data)
        sent = 0
        while sent < size:
            curr = size - sent
            if curr > Server.BUFF_SIZE:
                curr = Server.BUFF_SIZE
            curr_data = data[sent: sent + curr]
            curr_data += bytes(Server.BUFF_SIZE - len(curr_data))
            try:
                con.send(curr_data)
                sent += len(curr_data)
            except:  # noqa: Too broad exception clause
                print(f"Failed while sending a response to {con.getpeername()[0]}.")
                return False
        return True

    def handle_register_request(self, con: socket.socket, data: bytes) -> bool:
        print(f"Received registration request from {con.getpeername()[0]}.")
        req = protocol.RegistrationRequest()
        res = protocol.RegistrationResponse()
        if not req.unpack(data):
            print(f"Error: parsing registration request from {con.getpeername()[0]} failed.")
            return False
        if not utils.is_name_valid(req.name):
            print(f"Error: invalid name from {con.getpeername()[0]}.")
            return False
        if utils.is_name_exists(self.clients, req.name):
            print(f"Error: there is already a user with that name from {con.getpeername()[0]}.")
            res.header.code = protocol.ResponseCodes.REGISTER_FAILED.value
            res.cid = protocol.ID_SIZE * b'\x00'  # dummy id
            return self.write(con, res.header.pack())

        client = (utils.gen_new_uuid(self.clients), req.name, None, None)
        self.db.add_new_client(client)
        self.clients.append(client)
        # succeeded in adding the new client to the db, now prepare response
        res.cid = client[0]
        res.header.payload_size = protocol.ID_SIZE
        res.header.code = protocol.ResponseCodes.REGISTER_SUCCEEDED.value

        return self.write(con, res.pack())

    def handle_reconnect_request(self, con: socket.socket, data: bytes) -> bool:
        print(f"Received reconnection request from {con.getpeername()[0]}.")
        req = protocol.RegistrationRequest()
        if not req.unpack(data):
            print(f"Error: parsing reconnection request from {con.getpeername()[0]} failed.")
            return False
        if not utils.is_id_exists(self.clients, req.header.cid) or not utils.is_public_key_exists(self.clients, req.header.cid):
            print(f"Error: client doesnt exist in system or "
                  f"missing public key in reconnect request from {con.getpeername()[0]}.")
            # send reconnect failed response
            res = protocol.RegistrationResponse()
            res.header.code = protocol.ResponseCodes.RECONNECT_FAILED
            res.cid = req.header.cid
            return self.write(con, res.pack())
        res = protocol.PublicKeyResponse()
        res.cid = req.header.cid
        key = utils.gen_aes_key()  # generate new aes key
        self.db.set_aes_key(req.header.cid, key)  # save it in the db
        utils.set_aes_key_for_client(self.clients, req.header.cid, key)  # save it in the clients list
        public_key = self.db.get_public_key(req.header.cid)
        res.aes_key = utils.encrypt_public(key, public_key)
        res.header.code = protocol.ResponseCodes.RECONNECT_ACCEPTED.value
        res.header.payload_size = protocol.ID_SIZE + len(res.aes_key)

        print(f"Sending reconnection response to {con.getpeername()[0]}.")
        return self.write(con, res.pack())

    def handle_public_key_request(self, con: socket.socket, data: bytes) -> bool:
        print(f"Received public key request from {con.getpeername()[0]}.")
        req = protocol.PublicKeyRequest()
        if not req.unpack(data):
            print(f"Error: parsing public key request from {con.getpeername()[0]} failed.")
            return False
        print(f"Received public key from {con.getpeername()[0]}.")
        if not self.db.set_public_key(req.header.cid, req.public_key)\
                or not utils.set_public_key_for_client(self.clients, req.header.cid, req.public_key):
            return False
        key = utils.gen_aes_key()
        self.db.set_aes_key(req.header.cid, key)
        utils.set_aes_key_for_client(self.clients, req.header.cid, key)

        res = protocol.PublicKeyResponse()
        res.cid = req.header.cid
        res.aes_key = utils.encrypt_public(key, req.public_key)
        res.header.code = protocol.ResponseCodes.PUBLIC_KEY_RECEIVED.value
        res.header.payload_size = protocol.ID_SIZE + len(res.aes_key)

        print(f"Sending public key response to {con.getpeername()[0]}.")
        return self.write(con, res.pack())

    def handle_file_send_request(self, con: socket.socket, data: bytes) -> bool:
        print(f"Received file send request from {con.getpeername()[0]}.")
        req = protocol.FileSendRequest()
        if not req.unpack(data):
            print(f"Error: parsing file send request from {con.getpeername()[0]} failed.")
            return False

        decrypted_file = utils.decrypt_symmetric(req.file_content,
                                                 utils.get_aes_key(self.clients, req.header.cid))
        res = protocol.FileSendResponse()
        res.cid = req.header.cid
        res.content_size = len(decrypted_file)
        res.filename = req.filename
        res.checksum = utils.checksum(decrypted_file)
        res.header.payload_size = protocol.ID_SIZE + protocol.FILENAME_SIZE + 2 * protocol.COUNT_SIZE

        filename_decoded = req.filename.partition(b'\x00')[0].decode()
        # decrypt and save in system
        path = utils.save_file(req.header.cid,
                               filename_decoded,
                               decrypted_file)

        if self.db.is_file_exists(req.header.cid, filename_decoded):
            self.db.delete_file(req.header.cid, filename_decoded)

        # 0 as False for 'bit' SQLite data type
        self.db.add_file((req.header.cid, filename_decoded, path, 0))

        print(f"Sending file send response to {con.getpeername()[0]}.")
        return self.write(con, res.pack())

    def send_message_received(self, con: socket.socket, cid: bytes) -> bool:
        res = protocol.RegistrationResponse()
        res.header.code = protocol.ResponseCodes.MESSAGE_RECEIVED.value
        res.cid = cid
        return self.write(con, res.pack())

    def handle_crc_good_request(self, con: socket.socket, data: bytes) -> bool:
        print(f"Received good CRC request from {con.getpeername()[0]}.")
        req = protocol.CRCRequest()
        if not req.unpack(data):
            print(f"Error: parsing good CRC request from {con.getpeername()[0]} failed.")
            return False
        self.db.set_file_verified(req.header.cid, req.filename)

        print(f"Sending message received to {con.getpeername()[0]}.")
        return self.send_message_received(con, req.header.cid)

    def handle_crc_wrong_again_request(self, con: socket.socket, data: bytes) -> bool:
        print(f"Received wrong CRC sending again request from {con.getpeername()[0]}. Ignoring...")
        # do nothing
        # don't send message received, because the client will send the file again
        # just return to main loop and wait for the next request
        pass

    def handle_crc_wrong_done_request(self, con: socket.socket, data: bytes) -> bool:
        print(f"Received wrong CRC done request from {con.getpeername()[0]}.")
        req = protocol.CRCRequest()
        if not req.unpack(data):
            print(f"Error: parsing wrong CRC done request from {con.getpeername()[0]} failed.")
            return False

        print(f"Sending message received to {con.getpeername()[0]}.")
        return self.send_message_received(con, req.header.cid)

    def send_general_error_message(self, con: socket.socket) -> bool:
        res = protocol.RegistrationResponse()
        res.header.code = protocol.ResponseCodes.GENERAL_ERROR.value
        res.cid = b'\x00' * protocol.ID_SIZE  # dummy cid

        print(f"Sending general error message to {con.getpeername()[0]}.")
        return self.write(con, res.pack())
