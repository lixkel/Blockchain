import sqlite3
from time import time
import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1


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
            genesis = "00000001000000000000000000000000000000000000000000000000000000000000000085a72c861a7a66b699a6d11c90ea89290a72bd24ec38fc519b64e6185ccb79c60000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5F402B4000010c3101185374726f6ac3a1726e652073c3ba2075c5be20646f6d61215F44192B2d600920457746a9982804e49aff8f50d90cdba6ad8b8b76e3df79fc79a6ff1af2fb07557fb300e250f961c18c7db098e85387388e292cf78dd8ddb784d6636ac61e0e6ff566d2f37855ab3974a1a12d916e29f1fc7dc69a4b7c6a3ff62ea7b16e7b43da0ab812702140c2a3e59c4a9edc53e13db80b4091f4b4310ea7e20f7a0392066f8bd974991c003a5f8887f0a17f4c35064a58f224cb0afffffabc454a282028aa4f0949c73bbcd024725e5384554de420efb49d7f87ddafdf81ed1f72"
            self.c.execute("INSERT INTO test(hash, block) VALUES (self.hash(genesis[:216]), genesis))
            self.conn.commit()
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


    def verify_block(self, block):
        c.execute("SELECT * FROM TABLE WHERE ID = (SELECT MAX(ID) FROM TABLE);")
        previous_block = c.fetchone()
        if block[8:72] !== previous_block[2][8:72]:
            return False
        header_hash = self.hash(block[:216])
        block_target = int(header[136:200], 16)
        if not int(header_hash, 16) <= block_target:
            return False
        num_tx = int(block[216:218], 16)
        index = 218
        tx_remaining = 392
        tx_hashes = []
        for i in range(num_tx):
            message_size = int(block[index:index+2], 16)
            index += 2
            tx = block[index:index+message_size+tx_remaining]
            if not self.verify_tx(tx):
                return False
            tx_hashes.append(self.hash(tx))
            index = index + tx_size + tx_remaining
        merkle_root = self.merkle_tree(tx_hashes)
        if merkle_root != block[76:141]:
            return False


    def verify_tx(tx):
        sig = tx[-128:]
        vk = VerifyingKey.from_string(tx[-384:-256], curve=SECP256k1)
        if vk.verify(sig, bytes.fromhex(tx[:-128])):
            return True
        return False


    def hash(tx):
        return hashlib.sha256(bytes.fromhex(tx)).hexdigest()


    def merkle_tree(hashes):
        while len(hashes) != 1:
            hashes1 = []
            for i in range(0, len(hashes), 2):
                try:
                    to_hash = hashes[i] + hashes[i+1]
                except IndexError:
                    to_hash = hashes[i] + hashes[i]
                hashes1.append(self.hash(to_hash))
            hashes = hashes1
        return hashes[0]
