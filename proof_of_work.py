def mine(mined, to_mine):
    from hashlib import sha256
    import time
    while True:
        if not to_mine.empty():
            header, transactions = to_mine.get()
            target = int(header[136:200], 16)
            while True:
                for i in range(4294967295):
                    if not to_mine.empty():
                        comm = to_mine.get()
                        if comm == "stop":
                            break
                    nonce = hex(i)[2:]
                    prefix = 8 - len(nonce)
                    nonce = prefix * "0" + nonce
                    hash_result = sha256(bytes.fromhex(header + nonce)).hexdigest()
                    if int(hash_result, 16) <= target:
                        break
                if int(hash_result, 16) <= target or comm == "stop":
                    comm = None
                    mined.put(header + nonce + transactions)
                    break
                header = header[:200] + hex(int(time.time()))[:2]
