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
            self.c.execute("""CREATE TABLE test (
                id integer primary key AUTOINCREMENT,
                hash text,
                block text)
                """)
            genesis = "0000000100000000000000000000000000000000000000000000000000000000000000004e3d4fd77709f597fe3c5e24b4a8ac4be4f83fb1f3d95d37a7176d33834e45a20000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5F402B4000010c3101185374726f6ac3a1726e652073c3ba2075c5be20646f6d61215F44192B2d600920457746a9982804e49aff8f50d90cdba6ad8b8b76e3df79fc79a6ff1af2fb07557fb300e250f961c18c7db098e85387388e292cf78dd8ddb784d6636ac61e0e6ff566d2f37855ab3974a1a12d916e29f1fc7dc69a4b7c6a3ff62ea7b16e7b43da0ab812702140c2a3e59c4a9edc53e13db80b4091f4b4310ea7e20f7a0392066f8bd974991c003a5f8887f0a17f4c35064a58f224cb0afffffabc454a282028aa4f0949c73bbcd024725e5384554de420efb49d7f87ddafdf81ed1f72"
            self.c.execute("INSERT INTO test(hash, block) VALUES (hashlib.sha256(genesis[:216]).hexdigest(), genesis))
        try:
            keyFile = open("keyFile", "r")
            read = bytes.fromhex(keyFile.read())
            self.key = SigningKey.from_string(read, curve=SECP256k1)
        except:
            keyFile = open("keyFile", "w")
            self.key = SigningKey.generate(curve=SECP256k1)
            keyFile.write(self.key.to_string().hex())
        keyFile.close()
        self.ver_key = self.key.verifying_key
