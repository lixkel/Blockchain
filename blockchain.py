class Blockchain:
    def __init__(self, version, prnt, log):
        import sqlite3
        from time import time
        from os import urandom
        from hashlib import sha256
        from alter_chain import alter_chain
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        global time, urandom, alter_chain, sha256, serialization, Cipher, modes, ChaCha20, Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey, X25519PublicKey
        global logging
        logging = log
        self.version = version
        self.prnt = prnt
        self.conn = sqlite3.connect("blockchain.db")
        self.c = self.conn.cursor()
        self.mempool = []
        self.valid_tx = []
        self.pub_keys = {}
        self.orphans = {}
        self.alter_chains = []#[parent block rowid, chainwork, timestamp, [[hash, block],]]
        self.c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='blockchain'")
        if self.c.fetchone()[0] != 1:
            self.c.execute("""CREATE TABLE blockchain (
                hash TEXT,
                block TEXT,
                chainwork INTEGER)
                """)
            genesis = "000000010000000000000000000000000000000000000000000000000000000000000000801ab3730016697c66969993983e4ad1e4a4fba4044677f678c7b2a1ef8721c400000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5F402B4000154a8001185374726f6ac3a1726e652073c3ba2075c5be20646f6d61215F44192Bc61e0e6ff566d2f37855ab3974a1a12d916e29f1fc7dc69a4b7c6a3ff62ea7b16e7b43da0ab812702140c2a3e59c4a9edc53e13db80b4091f4b4310ea7e20f7a2d600920457746a9982804e49aff8f50d90cdba6ad8b8b76e3df79fc79a6ff1af2fb07557fb300e250f961c18c7db098e85387388e292cf78dd8ddb784d6636ab754d7da9a675c5b2035dbea64a353666c05a07653fc9df2c1f717fd6cadf181cf962f29534d37466a47d7a368607ca025c1672309f2f69a40bc466111deaace"
            gen_hash = self.hash(genesis[:216])
            gen_chainwork = int(2**256/int(genesis[136:200], 16))
            self.c.execute("INSERT INTO blockchain VALUES (?,?,?);", (gen_hash, genesis, gen_chainwork))
            self.conn.commit()
        try:
            keyFile = open("keyFile", "r")
            read = keyFile.read().split("\n")
            ed = bytes.fromhex(read[0])
            x = bytes.fromhex(read[1])
            self.private_key = Ed25519PrivateKey.from_private_bytes(ed)
            self.dh_private_key = X25519PrivateKey.from_private_bytes(x)
        except:
            keyFile = open("keyFile", "w")
            self.private_key = Ed25519PrivateKey.generate()
            private_bytes = self.private_key.private_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PrivateFormat.Raw,
                                encryption_algorithm=serialization.NoEncryption()
                                )

            self.dh_private_key = X25519PrivateKey.generate()
            dh_private_bytes = self.dh_private_key.private_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PrivateFormat.Raw,
                                encryption_algorithm=serialization.NoEncryption()
                                )
            keyFile.write(private_bytes.hex() + "\n" + dh_private_bytes.hex())
        keyFile.close()
        self.public_key = self.private_key.public_key()
        self.public_key_hex = self.public_key.public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw
                                )
        self.public_key_hex = self.public_key_hex.hex()

        self.dh_public_key = self.dh_private_key.public_key()
        self.dh_public_key_hex = self.dh_public_key.public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw
                                )
        self.dh_public_key_hex = self.dh_public_key_hex.hex()

        try:
            pubKeyFile = open("pubKeyFile", "r")
            all_keys = pubKeyFile.read().split("\n")[:-1]
            all_keys = all_keys
            for i in all_keys:
                pair = i.split()
                self.pub_keys[pair[0]] = [pair[1], pair[2]]
        except FileNotFoundError:
            pass
        self.c.execute("SELECT rowid, * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        entry = self.c.fetchone()
        self.height = entry[0]
        self.target = entry[2][136:200]
        self.chainwork = entry[3]
        print(f"height: {self.height}, target: {self.target}, chainwork: {self.chainwork}")


    def verify_block(self, block):
        block_target = block[136:200]
        block_target = int(block_target, 16)
        header_hash = self.hash(block[:216])
        if not int(header_hash, 16) <= block_target:
            print("block False")
            return False
        num_tx = int(block[216:218], 16)
        index = 218
        tx_remaining = 270
        tx_hashes = []
        for i in range(num_tx):
            tx_type = block[index:index+2]
            if not tx_type in ["00", "01", "02"]:
                return False
            if tx_type == "00":
                message_size = 64-4
            else:
                message_size = int(block[index+2:index+6], 16) * 2
                if tx_type == "01":
                    message_size += 32
            tx_size = index + message_size + tx_remaining
            tx = block[index:tx_size]
            if not self.verify_tx(tx, timestamp=block[200:208]):
                print("block False")
                return False
            tx_hashes.append(self.hash(tx))
            index += tx_size
        merkle_root = self.merkle_tree(tx_hashes)
        if merkle_root != block[72:136]:
            print("block False")
            return False
        print("block True")
        return True


    def verify_tx(self, tx, timestamp=None):
        global Ed25519PublicKey
        if tx in self.mempool or tx in self.valid_tx:
            print("tx True already have")
            return "already"
        sig = bytes.fromhex(tx[-128:])
        sender_pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx[-192:-128]))
        try:
            sender_pub_key.verify(sig, bytes.fromhex(tx[:-128]))
        except:
            print("tx sig False")
            return False
        tx_remaining = 270
        if tx[:2] == "01":
            tx_remaining += 32
        msg_size = len(tx) - tx_remaining
        tx_timestamp = int(tx[6+msg_size:14+msg_size], 16)
        if timestamp:
            timestamp = int(timestamp, 16)
            if not -1800 <= timestamp - tx_timestamp <= 1800:
                return False
            #ked bude temp fork a dojdu dva bloky s tymi istymi tx tak ich budem ma t dva krat v db
        elif not -1800 <= int(time()) - tx_timestamp <= 1800:
            return False
        print("tx True")
        return True


    def block_content(self, block):
        num_tx = int(block[216:218], 16)
        index = 218
        tx_remaining = 270
        for i in range(num_tx):
            tx_type = block[index:index+2]
            if tx_type == "00":
                message_size = 64-4
            else:
                message_size = int(block[index+2:index+6], 16) * 2
                if tx_type == "01":
                    message_size += 32
            tx_size = index + message_size + tx_remaining
            tx = block[index:tx_size]
            self.tx_content(tx)


    def tx_content(self, tx):
        if tx[-256:-192] == self.public_key_hex:
            type = tx[:2]
            peer_pub_key = tx[-192:-128]
            try:
                user = pub_keys[peer_pub_key]
            except KeyError:
                self.save_key(peer_pub_key)
                user = pub_keys[peer_pub_key]
            if type == "00":
                dh_peer_key = bytes.fromhex(tx[2:66])
                shared_key = private_key.exchange(dh_peer_key)
                derived_key = HKDF(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=None,
                                info=b'blockchain',
                                ).derive(shared_key)
                if user[1] != "sent":
                    send_message("send", cargo=["", peer_pub_key, "00"])
                pub_keys[peer_pub_key][2] = derived_key.hex()
            elif type == "01":
                nonce = tx[2:34]
                msg_size = int(tx[34:38], 16)
                if user[1] == "no" or user[1] == "sent":
                    if user[0] == "__unknown" and user[1] == "no":
                        del pub_keys[peer_pub_key]
                    print("sifrovana sprava ale neprebehla vymena klucov")
                    return False
                encryption_key = user[1]
                algorithm = ChaCha20(encryption_key, nonce)
                cipher = Cipher(algorithm, mode=None)
                decryptor = cipher.decryptor()
                msg = decryptor.update(ct)
                msg = msg.decode("utf-8")
                print(f"e {user[0]}: {msg}")
            elif type == "02":
                msg_size = int(tx[2:6], 16)
                msg = bytes.fromhex(tx[4:msg_size]).decode("utf-8")
                print(f"{user[0]}: {msg}")


    def hash(self, tx):
        global sha256
        return sha256(bytes.fromhex(tx)).hexdigest()


    def fill(self, entity, fill):
        lenght = len(entity)
        if lenght < fill:
            miss = fill - lenght
            entity = miss*"0" + entity
        return entity


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

    def save_key(self, new_key, nickname="__unknown"):
        file = open("pubKeyFile", "a")
        file.write(f"{new_key} {nickname} no\n")
        self.pub_keys[new_key] = [nickname, "no"]
        file.close()


    def create_tx(self, msg_type, msg, rec_key):
        global time, urandom
        if msg_type == "00":
            tx = self.dh_public_key_hex + hex(int(time()))[2:] + rec_key + self.public_key_hex
            tx = bytes.fromhex(tx)
        else:
            msg = msg.encode("utf-8")
            if msg_type == "01":
                for i in pub_keys:
                    if rec_key in pub_keys[i]:
                        key = pub_keys[i][2]
                if key == "no":
                    print("s pouzivatelom este neprebehla vymena klucov")
                nonce = urandom(16)
                algorithm = ChaCha20(key, nonce)
                cipher = Cipher(algorithm, mode=None)
                encryptor = cipher.encryptor()
                msg = encryptor.update(msg)
            msg = msg.hex()
            if len(msg) <= 1000:
                msg_size = self.fill(hex(len(msg))[2:], 4)
                msg_size = bytes.fromhex(msg_size)
                timestamp = hex(int(time()))[2:]
                tx = msg_size + msg + timestamp + rec_key + self.public_key_hex
                if msg_type == "01":
                    tx = nonce.hex() + tx
                tx = bytes.fromhex(tx)
            else:#tu treba dat aj
                print("sprava je prilis velka")
        signature = self.private_key.sign(tx)
        tx = tx + signature
        #na toto verify sa treba pozret ked dorobim verify_tx
        if self.verify_tx(tx.hex()) == True:
            return tx
        else:
            print("vytvorena tx je zla")
        return False


    def build_block(self):
        global time
        if len(self.mempool) >= 255:
            txs_num = "ff"
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


    def append(self, new_block, sync):
        new_block_hash = self.hash(new_block[:216])
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        previous_block = self.c.fetchone()[0]
        if new_block[8:72] != previous_block:
            self.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (new_block_hash,))
            in_blockchain = self.c.fetchone()
            try:
                in_orphans = self.orphans[new_block_hash]
            except KeyError:
                in_orphans = False
            in_alter = False
            for chain in self.alter_chains:
                for i in chain.chain:
                    if i[0] == new_block_hash:
                        in_alter = True
                        break
                if in_alter:
                    break
            if not in_blockchain and not in_orphans and not in_alter:
                self.c.execute("SELECT rowid, * FROM blockchain WHERE hash = (?);", (new_block[8:72],))
                alter = self.c.fetchone()
                if alter:
                    rowid = alter[0]
                    new_chainwork = alter[3] + int(2**256/int(new_block[136:200], 16))
                    self.alter_chains.append(alter_chain(rowid, new_chainwork, int(time()), hash=new_block_hash, block=new_block))
                    return "appended"
                for chain in self.alter_chains:
                    if chain.chain[-1][0] == new_block[8:72]:
                        chain.chainwork += int(2**256/int(new_block[136:200], 16))
                        chain.chain.append([new_block_hash, new_block, chain.chainwork])
                        if chain.chainwork > self.chainwork:
                            rowid = chain.parent + 1
                            alter_row = 0
                            alter_size = len(chain.chain)
                            self.alter_chains.append(alter_chain(chain.parent, 0, int(time())))
                            self.c.execute("SELECT MAX(rowid) FROM blockchain;")
                            max_rowid = self.c.fetchone()[0]
                            while rowid >= max_rowid and alter_row >= alter_size:
                                self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (rowid,))
                                set = self.c.fetchone()
                                self.alter_chains[-1].chain.append([set[0], set[1], set[2]])
                                self.alter_chains[-1].chainwork = set[2]
                                append_block = chain.chain[alter_row]
                                self.c.execute("UPDATE blockchain SET hash = (?) block = (?) chainwork = (?) WHERE rowid = (?);", (append_block[0], append_block[1], append_block[2], max_rowid))
                                self.block_content(append_block[1])
                                rowid += 1
                                alter_row += 1
                            while rowid <= max_rowid:
                                self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (rowid,))
                                set = self.c.fetchone()
                                self.alter_chains[-1].chain.append([set[0], set[1], set[2]])
                                self.alter_chains[-1].chainwork = set[2]
                                self.c.execute("DELETE FROM blockchain WHERE rowid=(?)", (rowid,))
                                rowid += 1
                            while alter_row < alter_size:
                                append_block = chain.chain[alter_row]
                                self.c.execute("INSERT INTO blockchain VALUES (?,?,?);", (append_block[0], append_block[1], append_block[2]))
                                self.block_content(append_block[1])
                                alter_row += 1
                            self.chainwork = chain.chainwork
                            self.alter_chains.remove(chain)
                            self.conn.commit()
                            self.c.execute("SELECT rowid FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
                            self.height = self.c.fetchone()[0]
                            if self.height % 10 == 0:
                                print("append calc_height")
                                self.calc_target()
                        return "appended"
                try:
                    a = self.orphans[new_block[8:72]]
                    return "alrdgot"
                except KeyError:
                    pass
                self.orphans[new_block[8:72]] = new_block
                return "orphan"
            else:
                return "alrdgot"
        block_target = new_block[136:200]
        if block_target != self.target:
            return False
        if sync and -360 <= int(time()) - int(new_block[208:216], 16) <= 360:
            print("append bad block timestamp")
            return False
        self.chainwork += int(2**256/int(block_target, 16))
        self.c.execute("INSERT INTO blockchain VALUES (?,?,?);", (new_block_hash, new_block, self.chainwork))
        self.conn.commit()
        self.block_content(new_block)
        self.height += 1
        if self.height % 10 == 0:
            print("append calc_height")
            self.calc_target()
        return True


    def calc_target(self):
        calc_height = self.height
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (calc_height,))
        heighest = int(self.c.fetchone()[1][200:208], 16)
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (calc_height - 9,))
        lowest = int(self.c.fetchone()[1][200:208], 16)
        difference = heighest - lowest
        change = float(difference) / 300.0
        if change > 4.0:
            change = 4.0
        elif change < 0.25:
            change = 0.25
        new_target = hex(int(float(int(self.target, 16)) * change))[2:]
        if len(new_target) < 64:
            dif = 64 - len(new_target)
            new_target = ("0" * dif) + new_target
        elif len(new_target) > 64:
            new_target = "f" * 64
        self.target = new_target
        print(f"difficulty change: {change}")
        print(f"new target: {self.target}")


    def check_orphans(self, param):#berie ako parameter hash blocku ku ktoremu pozrie ci v orphans nema child a potom zavola append a znovu check_orphans
        if param == "main":
            self.c.execute("SELECT hash FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
            top_hash = self.c.fetchone()[0]
        else:
            top_hash = param
        new = []
        try:
            orphan = self.orphans[top_hash]
            if self.append(orphan):
                del self.orphans[top_hash]
                new.append(self.hash(orphan[:216]))
                for i in self.check_orphans(self.hash(orphan[:216])):
                    new.append(orphan)
                return new
        except KeyError:
            pass
        return []
