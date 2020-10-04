class Blockchain:
    def __init__(self, version, prnt):
        import sqlite3
        from time import time
        from hashlib import sha256
        from ecdsa import SigningKey, VerifyingKey, SECP256k1
        global time, sha256, SigningKey, VerifyingKey, SECP256k1
        self.version = version
        self.prnt = prnt
        self.conn = sqlite3.connect("blockchain.db")
        self.c = self.conn.cursor()
        self.mempool = []
        self.pub_keys = {}
        self.target = "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        try:
            self.c.execute("SELECT * FROM blockchain")

        except:
            self.c.execute("""CREATE TABLE blockchain (
                hash text,
                block text)
                """)
            genesis = "000000010000000000000000000000000000000000000000000000000000000000000000801ab3730016697c66969993983e4ad1e4a4fba4044677f678c7b2a1ef8721c40000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5F402B4000005b0301185374726f6ac3a1726e652073c3ba2075c5be20646f6d61215F44192Bc61e0e6ff566d2f37855ab3974a1a12d916e29f1fc7dc69a4b7c6a3ff62ea7b16e7b43da0ab812702140c2a3e59c4a9edc53e13db80b4091f4b4310ea7e20f7a2d600920457746a9982804e49aff8f50d90cdba6ad8b8b76e3df79fc79a6ff1af2fb07557fb300e250f961c18c7db098e85387388e292cf78dd8ddb784d6636ab754d7da9a675c5b2035dbea64a353666c05a07653fc9df2c1f717fd6cadf181cf962f29534d37466a47d7a368607ca025c1672309f2f69a40bc466111deaace"
            gen_hash = self.hash(genesis[:216])
            self.c.execute("INSERT INTO blockchain VALUES (?,?);", (gen_hash, genesis))
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
        self.ver_key_str = self.ver_key.to_string().hex()

        try:
            pubKeyFile = open("pubKeyFile", "r")
            all_keys = pubKeyFile.read().split("\n")[:-1]
            all_keys = all_keys
            for i in all_keys:
                pair = i.split()
                self.pub_keys[pair[0]] = pair[1]
        except FileNotFoundError:
            pass


    def verify_block(self, block):
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        previous_block = self.c.fetchone()[0]
        if block[8:72] != previous_block:
            return False
        block_target = block[136:200]
        if block_target != self.target:
            return False
        block_target = int(block_target, 16)
        header_hash = self.hash(block[:216])
        if not int(header_hash, 16) <= block_target:
            return False
        num_tx = int(block[216:218], 16)
        index = 218
        tx_remaining = 392
        tx_hashes = []
        for i in range(num_tx):
            message_size = int(block[index:index+2], 16) * 2
            index += 2
            tx_size = index + message_size + tx_remaining
            tx = block[index+2:tx_size]
            if not self.verify_tx(tx):
                return False
            tx_hashes.append(self.hash(tx[2:]))
            index = index + tx_size
        merkle_root = self.merkle_tree(tx_hashes)
        if merkle_root != block[72:136]:
            return False
        return True


    def verify_tx(self, tx):
        global SigningKey, VerifyingKey, SECP256k1
        sig = bytes.fromhex(tx[-128:])
        vk = VerifyingKey.from_string(bytes.fromhex(tx[-256:-128]), curve=SECP256k1)
        if vk.verify(sig, bytes.fromhex(tx[2:-128])):
            if tx not in self.mempool:
                if tx[-384:-256] == self.ver_key_str:
                    msg_size = int(tx[:2], 16)
                    self.prnt.put(bytes.fromhex(tx[2:msg_size+2]).decode("utf-8"))
            return True
        return False


    def tx_content(self, tx):
        if self.for_me(tx):
            msg_size = int(tx[:2], 16)
            return bytes.fromhex(tx[2:msg_size+2]).decode("utf-8")
        return False


    def for_me(self, tx):
        if tx[-384:-256] == self.ver_key_str:
            return True
        return False


    def hash(self, tx):
        global sha256
        return sha256(bytes.fromhex(tx)).hexdigest()


    def merkle_tree(self, hashes):
        while len(hashes) > 1:
            hashes1 = []
            for i in range(0, len(hashes), 2):
                try:
                    to_hash = hashes[i] + hashes[i+1]
                except IndexError:
                    to_hash = hashes[i] + hashes[i]
                hashes1.append(self.hash(to_hash))
            hashes = hashes1
        if len(hashes) == 0:
            return "0" * 64
        return hashes[0]

    def save_key(self, new_key, nickname):
        file = open("pubKeyFile", "a")
        file.write(f"{new_key} {nickname}\n")
        self.pub_keys[new_key] = nickname
        file.close()


    def create_tx(self, msg, rec_key):
        global time
        if len(msg) <= 510:
            msg_size = hex(len(msg))[2:]
            if len(msg_size) % 2 == 1:
                msg_size = "0" + msg_size
            msg_size = bytes.fromhex(msg_size)
            timestamp = hex(int(time()))[2:]
            tx = msg + timestamp + rec_key + self.ver_key_str
            tx = bytes.fromhex(tx)
            signature = self.key.sign(tx)
            tx = msg_size + tx + signature
            if self.verify_tx(tx.hex()) == True:
                return tx
            else:
                print("tx je zla")
        else:
            print("sprava je prilis velka")
        return False


    def build_block(self):
        global time
        if len(self.mempool) >= 255:
            txs_num = hex(255)[2:]
        else:
            txs_num = hex(len(self.mempool))[2:]
        if len(txs_num) % 2 == 1:
            txs_num = "0" + txs_num
        txs = ""
        hashes = []
        for i in self.mempool:
              txs += i
              hashes.append(self.hash(i[2:]))
              if len(hashes) == 255:
                  break
        txs = txs_num + txs
        merkle_root = self.merkle_tree(hashes)
        timestamp = hex(int(time()))[2:]
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        previous_header = self.c.fetchone()[0]
        block_header = self.version + previous_header + merkle_root + self.target + timestamp
        return block_header, txs
