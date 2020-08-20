import sqlite3
from time import time
import hashlib
from ecdsa import SigningKey, SECP256k1


class Blockchain:
    def __init__(self):
        self.conn = sqlite3.connect("blockchain.db")
        self.c = self.conn.cursor()
        self.mempool = []
        try:
            self.c.execute("SELECT * FROM blockhain")
        except:
            c.execute("""CREATE TABLE test (
                id integer,
                hash text,
                block text)
                """)
        try:
            keyFile = open("keyFile", "r")
            read = bytes.fromhex(keyFile.read())
            self.key = SigningKey.from_string(read, curve=SECP256k1)
        except:
            keyFile = open("keyFile", "w")
            self.key = SigningKey.generate(curve=SECP256k1)
            keyFile.write(SigningKey.to_string().hex())
        keyFile.close()
        self.ver_key = self.key.verifying_key
