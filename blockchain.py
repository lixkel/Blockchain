class Blockchain:
    def __init__(self, version, prnt):
        import sqlite3
        from time import time
        from hashlib import sha256
        from alter_chain import alter_chain
        from ecdsa import SigningKey, VerifyingKey, SECP256k1
        global time, alter_chain, sha256, SigningKey, VerifyingKey, SECP256k1
        self.version = version
        self.prnt = prnt
        self.conn = sqlite3.connect("blockchain.db")
        self.c = self.conn.cursor()
        self.mempool = []
        self.pub_keys = {}
        self.orphans = {}
        self.alter_chains = []#[parent block rowid, chainwork, timestamp, [[hash, block],]]
        self.c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='blockchain'")
        if self.c.fetchone()[0] != 1:
            self.c.execute("""CREATE TABLE blockchain (
                hash TEXT,
                block TEXT)
                """)
            genesis = "000000010000000000000000000000000000000000000000000000000000000000000000801ab3730016697c66969993983e4ad1e4a4fba4044677f678c7b2a1ef8721c400000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5F402B4000154a8001185374726f6ac3a1726e652073c3ba2075c5be20646f6d61215F44192Bc61e0e6ff566d2f37855ab3974a1a12d916e29f1fc7dc69a4b7c6a3ff62ea7b16e7b43da0ab812702140c2a3e59c4a9edc53e13db80b4091f4b4310ea7e20f7a2d600920457746a9982804e49aff8f50d90cdba6ad8b8b76e3df79fc79a6ff1af2fb07557fb300e250f961c18c7db098e85387388e292cf78dd8ddb784d6636ab754d7da9a675c5b2035dbea64a353666c05a07653fc9df2c1f717fd6cadf181cf962f29534d37466a47d7a368607ca025c1672309f2f69a40bc466111deaace"
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
        self.c.execute("SELECT rowid FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        self.height = self.c.fetchone()[0]
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        self.target = self.c.fetchone()[1][136:200]
        print(self.target)
        try:
            save_file = open("save", "r")
            self.chainwork = int(bytes.fromhex(keyFile.read()))
        except FileNotFoundError and ValueError:
            if 'save_file' in locals():
                save_file.close()
            save_file = open("save", "w")
            c.execute("SELECT rowid FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
            max_rowid = c.fetchone()[0]
            if max_rowid == 0:
                return
            self.chainwork = 0
            for i in range(2, max_rowid+1):
                self.c.execute("SELECT block FROM blockchain WHERE rowid = (?);", (i,))
                block = self.c.fetchone()[0]
                target = block[136:200]
                self.chainwork += int(2**256/int(target, 16))
            save_file.write(str(self.chainwork))


    def verify_block(self, block):
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
            tx = block[index-2:tx_size]
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
        print(tx)
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


    def append(self, new_block):
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
            for chain in alter_chains:
                for i in chain[3]:
                    if i[0] == new_block_hash:
                        in_alter = True
                        break
                if in_alter:
                    break
            if not in_blockchain and not in_orphans and not in_alter:
                self.c.execute("SELECT rowid FROM blockchain WHERE hash = (?);", (new_block[8:72],))
                alter = self.c.fetchone()
                if alter:
                    rowid = alter[0]
                    new_chainwork = int(2**256/int(new_block[136:200], 16))
                    self.alter_chains.append(alter_chain(rowid, new_chainwork, int(time()), hash=new_block_hash, block=new_block))
                    return "appended"
                for chain in alter_chains:
                    if chain.chain[-1][0] == new_block[8:72]:
                        chain[3].append([new_block_hash, new_block])
                        chain[1] += int(2**256/int(new_block[136:200], 16))
                        if chain[1] > self.chainwork:
                            rowid = chain[0] + 1
                            alter_row = 0
                            alter_size = len(chain.chain)
                            self.alter_chains.append(alter_chain(chain[0], self.chainwork, int(time()))
                            self.c.execute("SELECT MAX(rowid) FROM blockchain;")
                            max_rowid = self.c.fetchone()[0]
                            while rowid >= max_rowid and alter_row >= alter_size:
                                self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (rowid,))
                                set = self.c.fetchone()
                                self.alter_chains[-1].chain.append([set[0], set[1]])
                                self.c.execute("UPDATE blockchain SET hash = (?) block = (?) WHERE rowid = (?);", (chain.chain[alter_row][0], chain.chain[alter_row][1], max_rowid))
                                rowid += 1
                                alter_row += 1
                            while rowid =< max_rowid:
                                c.execute("DELETE FROM blockchain WHERE rowid=(?)", (rowid,))
                                rowid += 1
                            while alter_row =< alter_size:
                                self.c.execute("INSERT INTO blockchain VALUES (?,?);", (chain.chain[alter_row][0], chain.chain[alter_row][1]))
                                alter_row += 1
                            self.chainwork = chain.chainwork
                            self.alter_chains.remove(chain)
                            conn.commit()
                        return "appended"
#treba popremislat nad check orphans
                self.orphans[new_block[8:72]] = new_block
                return "oprhan"
            else:
                return "alrdgot"
        block_target = new_block[136:200]
        if block_target != self.target:
            return False
        self.c.execute("INSERT INTO blockchain VALUES (?,?);", (new_block_hash, new_block))
        self.conn.commit()
        self.height += 1
        self.chainwork += int(2**256/int(block_target, 16))
        if self.height % 10 == 0:
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
        print(change)
        print(self.target)


    def check_orphans(self, param):
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
