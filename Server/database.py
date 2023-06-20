import datetime
import random
import sqlite3

from utils import is_file_exists

ID_LENGTH = 16


# print a db error in a specific format
def print_db_error(error) -> None:
    print(f"Error in database: {error}")


class Database:
    def __init__(self, filename):
        self.filename = filename

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.filename)
        return con

    def execute_script(self, sql: str, args=()) -> bool:
        con = None
        try:
            con = self.connect()
            cur = con.cursor()
            cur.execute(sql, args)
            con.commit()
            return True
        except sqlite3.Error as e:
            print_db_error(e)
            return False
        finally:
            con.close()

    def execute_query(self, query: str, args=(), commit=False) -> list:
        con = None
        try:
            con = sqlite3.connect(self.filename)
            cur = con.cursor()
            cur.execute(query, args)
            res = cur.fetchall()
            if commit:
                con.commit()
            return res
        except sqlite3.Error as e:
            print_db_error(e)
        finally:
            con.close()

    # return True if the database of the given name exists
    def is_db_exists(self) -> bool:
        return is_file_exists(self.filename)

    # create a new database having the required tables given the desired name
    def create_tables(self) -> None:
        create_clients_table_query = """CREATE TABLE clients(ID BLOB(16) not null PRIMARY KEY,
                                                                 Name VARCHAR(255) not null UNIQUE,
                                                                 PublicKey BLOB(160),
                                                                 LastSeen TIMESTAMP not null,
                                                                 AESKey BLOB(16));"""

        create_files_table_query = """CREATE TABLE files(ID BLOB(16) not null,
                                                         Filename VARCHAR(255) not null,
                                                         Path VARCHAR(255) not null UNIQUE,
                                                         Verified BIT not null default 0,
                                                         PRIMARY KEY (ID, FILENAME),
                                                         FOREIGN KEY (ID) REFERENCES clients(ID));"""

        self.execute_script(create_clients_table_query)
        self.execute_script(create_files_table_query)

    # fetch the list of all users from the db
    # returns a list of tuples where each tuple is a user
    def get_clients_list(self) -> list:
        if not self.is_db_exists():
            return []
        return self.execute_query("""SELECT * FROM clients""", ())

    # add a new client to the database
    # accepts the filename of the db and a tuple of (ID, Name, PublicKey, AESKey)
    # sets the LastSeen field to be now
    def add_new_client(self, client: tuple) -> None:
        if len(client) != 4:
            raise Exception("Invalid user values/format")

        add_client_query = """INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey)
                                      VALUES (?,?,?,?,?)"""

        self.execute_query(add_client_query, client[:3] + (datetime.datetime.now(),) + client[3:], commit=True)

    # check if already exists a client with given name
    def is_name_exists(self, name: str) -> bool:
        results = self.execute_query("""SELECT * FROM clients WHERE Name = ?""", (name,))
        return len(results) > 0

    def is_id_exists(self, uuid: bytes) -> bool:
        results = self.execute_query("""SELECT * FROM clients WHERE ID = ?""", (uuid,))
        return len(results) > 0

    def is_public_key_exists(self, uuid: bytes) -> bool:
        results = self.execute_query("""SELECT * FROM clients WHERE ID = ?""", (uuid,))
        return not results[0][2] is None

    def is_file_exists(self, client: bytes, filename: str) -> bool:
        results = self.execute_query("""SELECT * FROM files WHERE ID = ? AND Filename = ?""", (client, filename, ))
        return len(results) > 0

    def delete_file(self, client: bytes, filename: str) -> bool:
        return self.execute_script("""DELETE FROM files WHERE ID = ? AND Filename = ?""", (client, filename,))

    # update the LastSeen field of a specific client passed by his ID to now
    # client - 16 bytes of client ID
    def update_LastSeen(self, client: bytes) -> None:
        update_query = """UPDATE clients SET LastSeen = ? WHERE ID = ?"""
        self.execute_query(update_query, (datetime.datetime.now(), client), commit=True)

    # generate a new uuid for a new user
    def gen_new_uuid(self):
        rand = random.Random()
        while True:
            uuid = rand.randbytes(ID_LENGTH)
            if len(self.execute_query("SELECT * FROM clients WHERE ID = ?", (uuid,))) == 0:
                return uuid

    def get_public_key(self, client: bytes) -> bytes:
        results = self.execute_query("""SELECT PublicKey FROM clients WHERE ID = ?""", (client,))
        if not results:
            print_db_error("wrong uuid when fetching for public key")
            return None  # noqa: IncompatibleReturnValue
        # select the first (and only) row in the list and the first (and only) argument in the tuple
        return results[0][0]

    def set_public_key(self, client: bytes, key: bytes) -> bool:
        return self.execute_script("""UPDATE clients
                                      SET PublicKey = ?
                                      WHERE ID = ?""", (key, client,))

    def set_aes_key(self, client: bytes, key: bytes) -> bool:
        return self.execute_script("""UPDATE clients
                                      SET AESKey = ?
                                      WHERE ID = ?""", (key, client,))

    def get_aes_key(self, client: bytes) -> bytes:
        results = self.execute_query("""SELECT AESKey FROM clients WHERE ID = ?""", (client,))
        return results[0][0]

    def add_file(self, file: tuple) -> bool:
        if len(file) != 4:
            return False
        return self.execute_script("""INSERT INTO files (ID, Filename, Path, Verified)
                                      VALUES (?,?,?,?)""", file)

    def set_file_verified(self, client: bytes, filename: str):
        return self.execute_script("""UPDATE files
                                      SET Verified = 1
                                      WHERE ID = ? AND Filename = ?""", (client, filename,))
