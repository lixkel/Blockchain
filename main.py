from setup import *


def handle_message(soc, message):
    global version, nodes, sync, expec_blocks, my_addr, con_sent
    command = bytes.fromhex(message[:24].lstrip("0")).decode("utf-8")
    payload = message[32:]
    logging.debug(f"{getpeername(soc)}: {command}")
    if command == "version":
        if nodes[getpeername(soc)].expecting == "version":
            node_version = payload[:8]
            if node_version != version:
                return
            if int(node_version, 16) > int(version, 16):
                logging.debug("old version")
                print("vyzera to ze mas zastaralu verziu")
            best_height = int(payload[-20:-12], 16)
            nodes[getpeername(soc)].best_height = best_height
            my_addr = decode_ip(payload[-12:-4])
            logging.debug(f"my_addr: {my_addr}")
            tr_port = int(payload[-4:], 16)
            nodes[getpeername(soc)].port = tr_port
            logging.debug(f"node property: {tr_port}")
            timestamp = int(payload[8:24], 16)
            time_difference = int(int(time()) - timestamp)
            if -300 < time_difference > 300:
                return
            if nodes[getpeername(soc)].inbound:
                send_message("version", nodes[getpeername(soc)].socket)
                nodes[getpeername(soc)].expecting = "verack"
            else:
                send_message("only", soc=nodes[getpeername(soc)].socket, cargo="verack")
                nodes[getpeername(soc)].authorized = True
                nodes[getpeername(soc)].expecting = ""
                send_message("addr", soc=nodes[getpeername(soc)].socket, cargo="init")
                send_message("only", soc=list(nodes.values())[0].socket, cargo="getaddr")
                if getpeername(soc) not in hardcoded_nodes:
                    send_message("sync", soc=soc)
                peer = nodes[getpeername(soc)]
                c.execute("UPDATE nodes SET timestamp = (?) WHERE addr = (?) AND port = (?);", (peer.lastrecv, peer.address[0], peer.port))
                con_sent = False
    elif command == "verack":
        if nodes[getpeername(soc)].expecting == "verack":
            nodes[getpeername(soc)].authorized = True
            nodes[getpeername(soc)].expecting = ""
        else:
            logging.debug(f"{command} bancheck")
            ban_check(getpeername(soc))
    elif command == "transaction":
        if nodes[getpeername(soc)].authorized == True:
            result = blockchain.verify_tx(payload)
            if result == True:
                #mal by som to spreavit tak aby sa checkovalo len raz ci je tx v mempool
                #vymazava sa z mempoolu?
                logging.debug(payload)
                blockchain.valid_tx.append(payload)
                blockchain.mempool.append(payload)
                blockchain.tx_content(payload)
                send_message("broadcast", soc=getpeername(soc), cargo=[payload, "transaction"])
            elif result == "already":
                pass
            else:
                logging.debug(f"{command} 1 bancheck")
                ban_check(getpeername(soc))
        else:
            logging.debug(f"{command} 2 bancheck")
            ban_check(getpeername(soc))
    elif command == "headers":
        logging.debug(f"headers msg: {payload}")
        logging.debug(f"headers sync: {sync}")
        if payload == "00":
            print("Blockchain synced")
            sync = [True, 0, 0]
            return
        if not sync[0] and sync[2] == getpeername(soc):
            sync[1] = 0
        num_headers = int(payload[:2],16)
        num_hashes = 0
        index = 2
        getblocks = ""
        for i in range(num_headers):
            header_hash = payload[index:index+64]
            blockchain.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (header_hash,))
            result = blockchain.c.fetchone()
            if result == None:
                logging.debug(f"requested: {header_hash}")
                getblocks += header_hash
                expec_blocks += 1
                num_hashes += 1
            index += 64
        new_message = blockchain.fill(hex(num_hashes)[2:], 2) + getblocks
        send_message("universal", soc=soc, cargo=(new_message, "getblocks"))
    elif command == "getblocks":#toto by mohol poslat hocikto to by som mal riesit
        num_headers = int(payload[:2],16)
        index = 2
        for i in range(num_headers):
            header_hash = payload[index:index+64]
            logging.debug(f"getblocks hash: {header_hash}")
            blockchain.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (header_hash,))
            result = blockchain.c.fetchone()
            if result:
                block = result[1]
                send_message("universal", soc=soc, cargo=(block, "block"))
            else:
                logging.debug("dojebana picovina")
            index += 64
    elif command == "block":
        logging.debug(f"new block: {payload}")
        block_hash = blockchain.hash(payload[:216])
        expec_blocks -= 1
        logging.debug(f"expec_blocks: {expec_blocks}")
        if blockchain.verify_block(payload):
            appended = blockchain.append(payload, sync[0])
            logging.debug(f"block appended: {appended}")
            if appended == "orphan":
                if sync[0] == False and expec_blocks == 0 and sync[1] == 0:
                    logging.debug("block posielam sync")
                    send_message("sync", soc=soc)
                    return
                if sync[0]:
                    new_message = "01" + payload[8:72]
                    send_message("universal", soc=soc, cargo=[new_message, "getblocks"])
                    expec_blocks += 1
                return
            elif appended == "alrdgot":
                if sync[0] == False and expec_blocks == 0 and sync[1] == 0:
                    logging.debug("block posielam sync")
                    send_message("sync", soc=soc)
                    return
                return
            elif appended == "appended":
                if sync[0]:
                    new_message = "01" + block_hash
                    send_message("broadcast", soc=getpeername(soc), cargo=[new_message, "headers"])
                if sync[0] == False and expec_blocks == 0:
                    logging.debug("block posielam sync")
                    send_message("append sync", soc=soc, cargo=block_hash)
                blockchain.check_orphans(block_hash)
                return
            elif appended == True:
                orphans = blockchain.check_orphans("main")
                print(f"new valid block received")
            else:
                logging.debug(f"{command} 1 bancheck")
                ban_check(getpeername(soc))
                return
        else:
            logging.debug(f"{command} 2 bancheck")
            ban_check(getpeername(soc))
            return
        logging.debug(f"sync: {sync}")
        if sync[0] == False and expec_blocks == 0:
            logging.debug("block posielam sync")
            send_message("sync", soc=soc)
            return
        if not sync[0]:
            return
        if mining:
            logging.debug("stopping mining")
            to_mine.put("stop")
            start_mining()
        num_headers = 1
        headers = block_hash
        if 'orphans' in locals():
            for i in orphans:
                headers += i
                num_headers += 1
        num_headers = blockchain.fill(hex(num_headers)[2:], 2)
        new_message = num_headers + headers
        send_message("broadcast", soc=getpeername(soc),  cargo=[new_message, "headers"])
    elif command == "getheaders":
        logging.debug(f"getheaders sync: {sync}")
        if not sync[0] and sync[2] != getpeername(soc):
            return
        elif not sync[0] and sync[2] == getpeername(soc):
            print("Blockchain synced")
            sync = [True, 0, 0]
        chainwork = int(payload[:64], 16)
        if blockchain.chainwork < chainwork:#tu by sa potom dal dat ze expect sync ak to budem chciet robit cez
            logging.debug("node ma vacsi chainwork")
            send_message("sync", soc=soc)
            return
        num_hash = int(payload[64:66])
        size = 64 + 2 + ((num_hash + 1) * 64)
        if len(payload) == size:
            stop_hash = payload[-64:]
            start_hash = payload[66:130]
            index = 130
            for i in range(num_hash):
                blockchain.c.execute("SELECT rowid FROM blockchain WHERE hash = (?);", (start_hash,))
                rowid = blockchain.c.fetchone()
                if rowid != None:
                    break
                index += 64
                start_hash = payload[index:index+64]
            if rowid == None:
                logging.debug("getheaders none")
                rowid = 1
            else:
                rowid = rowid[0]
            blockchain.c.execute("SELECT rowid FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
            max_rowid = blockchain.c.fetchone()[0]
            logging.debug(f"rowid: {rowid}")
            logging.debug(f"maxrowid: {max_rowid}")
            if rowid and rowid != max_rowid:
                new_message = ""
                num_headers = 0
                for i in range(255):#toto bude este treba fixnut ked to bude nad 255
                    blockchain.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (rowid,))
                    block = blockchain.c.fetchone()
                    if block:
                        new_message += block[0]
                        num_headers += 1
                        if block[0] == stop_hash:
                            num_headers = hex(num_headers)[2:]
                            num_headers = blockchain.fill(num_headers, 2)
                            new_message = num_headers + new_message
                            send_message("universal", soc=soc, cargo=[new_message, "headers"])
                            return
                    else:
                        break
                    rowid += 1
                num_headers = hex(num_headers)[2:]
                num_headers = blockchain.fill(num_headers, 2)
                new_message = num_headers + new_message
                send_message("universal", soc=soc, cargo=[new_message, "headers"])
            elif rowid == max_rowid:
                send_message("universal",soc=soc, cargo=["00", "headers"])
        else:
            logging.debug(f"{command} 3 bancheck")
            ban_check(getpeername(soc))
    elif command == "getaddr":
        send_message("addr", soc=soc)
    elif command == "addr":
        logging.debug(f"addr payload: {payload}")
        num_addr = int(payload[:4], 16)
        if num_addr > 1000:
            logging.debug(f"{command} bancheck")
            ban_check(getpeername(soc))
            return
        index = 4
        logging.debug(f"my addr:{my_addr}, {port}")
        for i in range(num_addr):
            node_ip = decode_ip(payload[index:index+8])
            node_port = int(payload[index+8:index+12], 16)
            node_timestamp = int(payload[index+12:index+20], 16)
            logging.debug(f"node: {node_ip}, {node_port}, {node_timestamp}")
            if (node_ip, node_port) in hardcoded_nodes:
                continue
            if node_ip == "127.0.0.1" or node_ip == "0.0.0.0":
                return
            index += 20
            c.execute("SELECT * FROM nodes WHERE addr = (?) AND port = (?);", (node_ip, node_port))
            query = c.fetchone()
            logging.debug(f"query {query}")
            if (node_ip != my_addr or node_port != port) and query == None:
                c.execute("INSERT INTO nodes VALUES (?,?,?);", (node_ip, node_port, node_timestamp))
            elif (node_ip != my_addr or node_port != port) and query != None:
                if query[2] < node_timestamp:
                    c.execute("UPDATE nodes SET timestamp = (?) WHERE addr = (?) AND port = (?);", (node_timestamp, node_ip, node_port))
            if num_addr == 1 and int(time()) - node_timestamp < 600 and (node_ip != my_addr or node_port != port) and routable(node_ip):
                address = getpeername(soc)
                if query != None:
                    if query[0] == node_ip and query[1] == node_port and query[2] == node_timestamp:
                        break
                if len(nodes) <= 1:
                    break
                elif len(nodes) == 2:
                    for i in list(nodes.values()):
                        if i.address != address:
                            send_message("addr", soc=i.socket, cargo=payload)
                    break
                while True:
                    logging.debug("loop addr preposielanie")
                    first = randint(0, len(nodes)-1)
                    second = randint(0, len(nodes)-1)
                    if first != second and address != list(nodes.values())[first].address and address != list(nodes.values())[second].address:
                        send_message("addr", soc=list(nodes.values())[first].socket, cargo=payload)
                        send_message("addr", soc=list(nodes.values())[second].socket, cargo=payload)
                        break
        conn.commit()
    elif command == "active":
        pass
    else:
        logging.debug(f"{command} bancheck")
        ban_check(getpeername(soc))


def send_message(command, soc = None, cargo = None):
    global version, nodes, port, sync
    if command == "version" or command == "version1":
        timestamp = hex(int(time()))[2:]
        best_height = hex(blockchain.height)[2:]
        best_height = blockchain.fill(best_height, 8)
        if command == "version1":
            addr_recv = cargo
        else:
            addr_recv = getpeername(soc)[0]
        addr_recv = encode_ip(addr_recv)
        tr_port = blockchain.fill(hex(port)[2:], 4)
        payload = bytes.fromhex(version + timestamp + best_height + addr_recv + tr_port)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("version", payload_lenght)
        if command == "version1":
            return header + payload
        outbound.put(["send", [soc, header + payload]])
    elif command == "send":
        msg, pub_key, msg_type = cargo
        payload = blockchain.create_tx(msg_type ,msg, pub_key)
        blockchain.mempool.append(payload.hex())
        payload_lenght = hex(len(payload))[2:]
        logging.debug("idem sendovat")
        header = create_header("transaction", payload_lenght)
        outbound.put(["broadcast", [soc, header + payload]])
    elif command == "broadcast":
        payload, type = cargo
        payload = bytes.fromhex(payload)
        payload_lenght = hex(len(payload))[2:]
        header = create_header(type, payload_lenght)
        outbound.put(["broadcast", [soc, header + payload]])
    elif command == "universal":
        cargo, type = cargo
        payload = bytes.fromhex(cargo)
        payload_lenght = hex(len(payload))[2:]
        header = create_header(type, payload_lenght)
        outbound.put(["send", [soc, header + payload]])
    elif command == "sync":
        print("Synchronizujem zo sietou")
        sync = [False, int(time()), getpeername(soc)]
        num_headers = 0
        blockchain.c.execute("SELECT rowid FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        rowid = blockchain.c.fetchone()[0]
        if rowid < 50:
            blockchain.c.execute("SELECT hash FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
            block_headers = blockchain.c.fetchone()[0]
            num_headers = 1
        else:
            change = int(rowid / 10)
            block_headers = ""
            for i in range(9):
                blockchain.c.execute("SELECT hash FROM blockchain WHERE rowid = (?);", (rowid,))
                block_headers += blockchain.c.fetchone()[0]
                rowid -= change
                num_headers += 1
        payload = bytes.fromhex(blockchain.fill(hex(blockchain.chainwork)[2:], 64) + blockchain.fill(hex(num_headers)[2:], 2) + block_headers + "0"*64)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("getheaders", payload_lenght)
        outbound.put(["send", [soc, header + payload]])
    elif command == "append sync":
        payload = bytes.fromhex(blockchain.fill(hex(blockchain.chainwork)[2:], 64) + "01" + cargo + "0"*64)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("getheaders", payload_lenght)
        outbound.put(["send", [soc, header + payload]])
    elif command == "addr":
        if cargo == "init" or cargo == "broadcast":
            payload = bytes.fromhex("0001" + encode_ip(my_addr) + blockchain.fill(hex(port)[2:], 4) + hex(int(time()))[2:])
        elif cargo != None and cargo != "broadcast":
            payload = bytes.fromhex(cargo)
        else:
            timestamp = int(time()) - 18000
            c.execute("SELECT * FROM nodes WHERE timestamp > ?;", (timestamp,))
            ls_nodes = c.fetchall()
            logging.debug(f"ls_nodes addr: {ls_nodes}")
            if ls_nodes == []:
                return
            num_addr = 0
            payload = ""
            for node in ls_nodes:
                peer = getpeername(soc)
                if node[0] != peer[0] and node[1] != peer[1]:
                    num_addr += 1
                    payload = payload + encode_ip(node[0]) + blockchain.fill(hex(node[1])[2:], 4) + hex(node[2])[2:]
                elif len(ls_nodes) == 1:
                    return
                if num_addr == 1000:
                    break
            payload = bytes.fromhex(blockchain.fill(hex(num_addr)[2:], 4) + payload)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("addr", payload_lenght)
        if cargo == "broadcast":
            outbound.put(["broadcast", [soc, header + payload]])
        else:
            outbound.put(["send", [soc, header + payload]])
    elif command == "only":
        header = create_header(cargo, "0")
        outbound.put(["send", [soc, header]])


def create_header(command, payload_lenght):
    return bytes.fromhex(blockchain.fill(command.encode("utf-8").hex(), 24) + blockchain.fill(payload_lenght, 8))


def encode_ip(ip):
    ip = ip.split(".")
    addr = ""
    for i in ip:
        if 0 > int(i) > 255:
            print("neplatna adresa")
            return
        temp = hex(int(i))[2:]
        addr += blockchain.fill(temp, 2)
    return addr


def decode_ip(ip):
    previ = -1
    addr = ""
    for i in range(2, 10, 2):
        if i == 2:
            addr = str(int(ip[-i:], 16)) + "." + addr
        else:
            addr = str(int(ip[-i:previ], 16)) + "." + addr
        previ = -i
    return addr[:-1]


def ban_check(address):
    logging.debug("bancheck")
    try:
        logging.debug(f"ban nodes: {nodes}")
        logging.debug(f"ban addr: {address}")
        nodes[address].banscore += 1
        if nodes[address].banscore >= 10:
            c.execute("DELETE FROM nodes WHERE addr=(?) AND port=(?)", (address[0], address[1]))
            outbound.put(["close", address])
            ban_list.append(address)
    except KeyError:
        logging.debug("ban_check key error")
        pass


def routable(ip):
    if ip == "0.0.0.0":
        return False
    elif ip == "127.0.0.1":
        return False
    ip_split = [int(i) for i in ip.split(".")]
    if ip_split[0] == 10:
        return False
    elif ip_split[0] == 192 and ip_split[1] == 168:
        return False
    elif ip_split[0] == 176 and 16 <= ip_split[1] <= 31:
        return False
    return True


def connect():
    global nodes, con_sent, c
    #aby som sa nepokusal pripojit na node na ktory uz som na jednom porte moze pocuvat len jeden node takze ak by bol tam aj druhy tak on moze robit len outbound
    node_list = [(i.address[0], i.port) for i in list(nodes.values())]
    c.execute("SELECT * FROM nodes ORDER BY RANDOM() LIMIT 1")
    query = c.fetchone()#bude cakat kym dostanem addr od con aby som dostal nove adresy!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if query == None:
        return
    line = (query[0], query[1])
    if line not in node_list and line not in ban_list:
        logging.debug(f"connectujem: {line}")
        outbound.put(["connect", [line[0], line[1], send_message("version1", cargo=line[0])]])
        con_sent = True

def start_mining():
    block_header, txs = blockchain.build_block()
    to_mine.put([block_header, txs])


def getpeername(soc):
    global nodes
    try:
        adr = soc.getpeername()
        return adr
    except:
        for i in list(nodes.keys()):
            try:
                nodes[i].socket.getpeername()
            except:
                del nodes[i]

def main():
    global sync, mining, con_sent, blockchain, stime, prev_time, num_time
    blockchain = Blockchain(version, send_message, sync, logging)
    local_node.start()

    c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='nodes'")
    if c.fetchone()[0] != 1:
        c.execute("""CREATE TABLE nodes (
            addr TEXT,
            port INTEGER,
            timestamp INTEGER)
            """)

    print("finding nodes...")
    c.execute("SELECT * FROM nodes;")
    if c.fetchall() == []:
        for i in hardcoded_nodes:
            sent = None
            outbound.put(["connect", [i[0], i[1], send_message("version1", cargo=i[0])]])
            started = int(time())
            while True:
                if not inbound.empty():
                    soc, message = inbound.get()
                    if message == "error":
                        logging.debug("error")
                        break
                    handle_message(soc, message)
                    if message[:24] == "000000000000000061646472":
                        logging.debug("msg je addr")
                        break
                if int(time()) - started > 10:
                    logging.debug("prekroceny cas")
                    break
            if len(nodes) != 0:
                outbound.put(["close", list(nodes.values())[0].address])
            c.execute("SELECT * FROM nodes;")
            if len(c.fetchall()) >= 8:
                outbound.put(["close", list(nodes.values())[0].address])
                break#treba zatvorit conection
    print("connecting...")

    tcli.start()

    try:
        while True:
            if len(nodes) < opt_nodes:
                if len(nodes) == 0 and int(time()) % 5 == 0 and int(time()) != prev_time:
                    prev_time = int(time())
                    c.execute("SELECT * FROM nodes;")
                    logging.debug(f"con_sent: {con_sent}")
                    logging.debug(c.fetchall())
                    print("connecting...")
                if not con_sent:
                    connect()#mozno by bolo lepsie spravit init connect v loope pred tymto
            if not inbound.empty():
                soc, message = inbound.get()
                if message == "error":
                    c.execute("DELETE FROM nodes WHERE addr=(?) AND port=(?)", (soc[0], soc[1]))
                    conn.commit()
                    con_sent = False
                else:
                    handle_message(soc, message)
            if not mined.empty():
                new_block = mined.get()
                logging.debug(f"new block mined: {new_block}")
                new_block_hash = blockchain.hash(new_block[:216])
                if blockchain.append(new_block, sync[0]) == True:
                    print("new block mined")
                    print(f"mempool: {blockchain.mempool}")
                    message = "01" + new_block_hash
                    send_message("broadcast", cargo=[message, "headers"])
                else:
                    logging.debug("block neappendnuty")
                start_mining()
            if int(time()) - stime > 1800:
                num_time += 1
                current_time = int(time())
                for tx in blockchain.valid_tx:
                    if not -1800 <= current_time - int(tx[-264:-256], 16) <= 1800:
                        blockchain.valid_tx.remove(tx)
                for i in list(nodes.values()):
                    c.execute("UPDATE nodes SET timestamp = (?) WHERE addr = (?) AND port = (?);", (i.lastrecv, i.address[0], i.port))
                    if current_time - i.lastrecv > 5400:
                        outbound.put(["close", i.address])
                    elif current_time - i.lastsend > 1800:
                        send_message("only", soc=nodes[getpeername(i.socket)].socket, cargo="active")
                if num_time == 48:
                    send_message("addr", cargo="broadcast")
                    c.execute("SELECT MAX(rowid) FROM nodes;")
                    rowid = c.fetchone()[0]
                    if len(nodes) >= 3 and rowid > 1000:
                        c.execute("DELETE FROM nodes WHERE timestamp<(?)", (stime, ))
                        num_time = 0
                stime = int(time())
                conn.commit()
            if not sync[0]:
                if sync[1] != 0 and  int(time()) - sync[1] > 30:
                    logging.debug(f"sync bancheck")
                    ban_check(sync[2])
                    print("Blockchain synced")
                    sync = [True, 0, 0]
            if not com.empty():
                a, b = com.get()
                logging.debug(f"cli a: {a}")
                logging.debug(f"cli b: {b}")
                if a == "con":
                    b, d = b
                    outbound.put(["connect", [b, d, send_message("version1", cargo=b)]])
                elif a == "send":
                    b, d, e = b
                    if b == "":
                        display.put(blockchain.pub_keys)
                    else:
                        if e == "0":
                            e = "02"
                        else:
                            e = "01"
                        pub_key = list(blockchain.pub_keys.keys())[b]
                        cargo = [d, pub_key, e]
                        send_message("send", cargo=cargo)
                elif a == "import":
                    b, d = b
                    blockchain.save_key(b, d)
                    cargo = ["", b, "00"]
                    send_message("send", cargo=cargo)
                elif a == "export":
                    display.put(blockchain.public_key_hex)
                elif a == "edit":
                    pub_key, new_name = b
                    pub_key = list(blockchain.pub_keys.keys())[pub_key]
                    blockchain.pub_keys[pub_key][0] = new_name
                    blockchain.edit_key_file(pub_key, new_name, 1)
                elif a == "lsimported":
                    display.put(blockchain.pub_keys)
                elif a == "lsnodes":
                    display.put(list(nodes.values()))
                elif a == "start mining":
                    if not sync[0]:
                        print("este niesi sync")
                        continue
                    print("minujeme")
                    start_mining()
                    mining = Process(target=mine, args=(mined, to_mine))
                    mining.start()
                elif a == "stop mining":
                    if mining:
                        mining.terminate()
                        mining = None
                        print("mining stopped")
                elif a == "nodesdb":
                    current_time = int(time())
                    c.execute("SELECT * FROM nodes")
                    nod = c.fetchall()
                    for i in nod:
                        print(f"address: {i[0]}, port: {i[1]}, from last time: {current_time-i[2]}")
                elif a == "highest":
                    blockchain.c.execute("SELECT rowid,* FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
                    row = blockchain.c.fetchone()
                    print(f"height: {row[0]}")
                    print(f"block hash: {row[1]}")
                    print(f"block: {row[2]}")
                elif a == "mine one":
                    start_mining()
                    mining = Process(target=mine, args=(mined, to_mine))
                    mining.start()
                    while mined.empty():
                        pass
                    new_block = mined.get()
                    print(f"new block mined: {new_block}")
                    new_block_hash = blockchain.hash(new_block[:216])
                    if blockchain.append(new_block, sync[0]) == True:
                        print("new block mined")
                        print(f"mempool: {blockchain.mempool}")
                        message = "01" + new_block_hash
                        send_message("broadcast", cargo=[message, "headers"])
                    else:
                        print("block neappendnuty")
                    mining.terminate()
                    mining = None
                elif a == "end":
                    outbound.put(["end", []])
                    local_node.join()
                    if mining:
                        mining.terminate()
                    break

    except:
        logging.error(traceback.format_exc())
        if mining:
            mining.terminate()
        outbound.put(["end", []])
        local_node.join()


if __name__ == '__main__':
    main()
