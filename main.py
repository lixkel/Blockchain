import socket
import select
import sqlite3
import hashlib
import threading
from time import time
from random import randint
from multiprocessing import Queue, Process
from ecdsa import SigningKey, VerifyingKey, SECP256k1

import p2p
from cli import cli
from node import node
from proof_of_work import mine
from blockchain import Blockchain

def handle_message(soc, message):
    global version
    global nodes
    global sync
    global expec_blocks
    global my_addr, con_sent
    command = bytes.fromhex(message[:24].lstrip("0")).decode("utf-8")
    payload = message[32:]
    print(command)
    if command == "version":
        if nodes[soc.getpeername()].expecting == "version":
            node_version = payload[:8]
            if node_version != version:
                return
            best_height = int(payload[-20:-12], 16)
            nodes[soc.getpeername()].best_height = best_height
            print(nodes[soc.getpeername()].best_height)
            my_addr = decode_ip(payload[-12:-4])
            print(my_addr)
            tr_port = int(payload[-4:], 16)
            nodes[soc.getpeername()].port = tr_port
            print(tr_port)
            timestamp = int(payload[8:24], 16)
            time_difference = int(int(time()) - timestamp)
            if -300 < time_difference > 300:
                return
            if nodes[soc.getpeername()].inbound:
                send_message("version", nodes[soc.getpeername()].socket)
                nodes[soc.getpeername()].expecting = "verack"
            else:
                send_message("only", soc=nodes[soc.getpeername()].socket, cargo="verack")
                nodes[soc.getpeername()].authorized = True
                nodes[soc.getpeername()].expecting = ""
                send_message("addr", soc=nodes[soc.getpeername()].socket, cargo="init")
                send_message("only", soc=list(nodes.values())[0].socket, cargo="getaddr")
    elif command == "verack":
        if nodes[soc.getpeername()].expecting == "verack":
            nodes[soc.getpeername()].authorized = True
            nodes[soc.getpeername()].expecting = ""
    elif command == "transaction":
        if nodes[soc.getpeername()].authorized == True:
            if blockchain.verify_tx(payload) == True:
                #mal by som to spreavit tak aby sa checkovalo len raz ci je tx v mempool
                if payload not in blockchain.mempool:
                    blockchain.mempool.append(payload)
                    send_message("broadcast", soc=soc.getpeername(), cargo=[payload, "transaction"])
                else:
                    pass
        else:
            ban_check(soc.getpeername())
    elif command == "headers":
        if payload == "00":
            sync = True
            return
        num_headers = int(payload[:2],16)
        index = 2
        getblocks = ""
        for i in range(num_headers):
            header_hash = payload[index:index+64]
            blockchain.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (header_hash,))
            result = blockchain.c.fetchone()
            if result == None:
                getblocks += header_hash
                expec_blocks += 1
            index += 64
        new_message = payload[:2] + getblocks
        send_message("universal", soc=soc, cargo=(new_message, "getblocks"))
    elif command == "getblocks":#toto by mohol poslat hocikto to by som mal riesit
        num_headers = int(payload[:2],16)
        index = 2
        for i in range(num_headers):
            header_hash = payload[index:index+64]
            blockchain.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (header_hash,))
            result = blockchain.c.fetchone()
            if result:
                block = result[1]
                send_message("universal", soc=soc, cargo=(block, "block"))
            else:
                print("dojebana picovina")
            index += 64
    elif command == "block":
        print(f"new block: {payload}")
        expec_blocks -= 1
        if blockchain.verify_block(payload):
            blockchain.append(payload)
        if sync == False and expec_blocks == 0:
            send_message("sync", soc=soc)
    elif command == "getheaders":
        if len(payload) == 128:
            start_hash = payload[:64]
            stop_hash = payload[64:]
            blockchain.c.execute("SELECT rowid FROM blockchain WHERE hash = (?);", (start_hash,))
            rowid = blockchain.c.fetchone()[0]
            if rowid:
                new_message = ""
                for i in range(255):#toto bude este treba fixnut ked to bude nad 255
                    rowid += 1
                    blockchain.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (rowid,))
                    block = blockchain.c.fetchone()
                    if block:
                        new_message += block[0]
                        if block[0] == stop_hash:
                            header_num = hex(i+1)[2:]
                            if len(header_num) % 2 == 1:
                                header_num = "0" + header_num
                            new_message = header_num + new_message
                            send_message("broadcast", cargo=[new_message, "headers"])
                            break
                    else:
                        if stop_hash == "0"*64:
                            header_num = hex(i)[2:]
                            if len(header_num) % 2 == 1:
                                header_num = "0" + header_num
                            new_message = header_num + new_message
                            send_message("broadcast", cargo=[new_message, "headers"])
                            break
    elif command == "getheader":
        send_message("addr", soc=soc)
    elif command == "addr":
        num_addr = int(payload[:4], 16)
        if num_addr > 1000:
            return
        elif num_addr > 1:
            con_sent = False
        index = 4
        for i in range(num_addr):
            node_ip = decode_ip(payload[index:index+8])
            node_port = int(payload[index+8:index+12], 16)
            node_timestamp = int(payload[index+12:index+20], 16)
            print(node_ip, node_port, node_timestamp)
            index += 20
            c.execute("SELECT * FROM nodes WHERE addr = (?) AND port = (?);", (node_ip, node_port))
            query = c.fetchone()
            if node_ip != my_addr and node_port != port and query == []:
                c.execute("INSERT INTO nodes VALUES (?,?,?);", (node_ip, node_port, node_timestamp))
            elif node_ip != my_addr and node_port != port and query != []:
                if query[3] < node_timestamp:
                    c.execute("UPDATE nodes timestamp = (?) WHERE addr = (?) AND port = (?);", (node_timestamp, node_ip, node_port))
            elif num_addr == 1 and int(time()) - node_timestamp < 600:
                address = soc.getpeername()
                if query != []:
                    if query[0] == node_ip and query[1] == node_port and query[2] == node_timestamp:
                        return
                if len(nodes) =< 1:
                    return
                elif len(nodes) == 2:
                    for i in list(nodes.values()):
                        if i.address != address:
                            send_message("addr", soc=i.socket, cargo=payload)
                while True:
                    first = randint(0, len(nodes))
                    second = randint(0, len(nodes))
                    if first != second and address != list(nodes.values())[first].address and address != list(nodes.values())[second].address:
                        send_message("addr", soc=list(nodes.values())[first].socket, cargo=payload)
                        send_message("addr", soc=list(nodes.values())[second].socket, cargo=payload)
                        break
        conn.commit()
    elif comm == "active":
        pass
    else:
        ban_check(soc.getpeername())


def send_message(command, soc = None, cargo = None):
    global version
    global nodes
    global port
    if command == "version" or command == "version1":
        timestamp = hex(int(time()))[2:]
        best_height = hex(blockchain.height)[2:]
        best_height = fill(best_height, 8)
        if command == "version1":
            addr_recv = cargo
        else:
            addr_recv = soc.getpeername()[0]
        addr_recv = encode_ip(addr_recv)
        tr_port = fill(hex(port)[2:], 4)
        payload = bytes.fromhex(version + timestamp + best_height + addr_recv + tr_port)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("version", payload_lenght)
        if command == "version1":
            return header + payload
        outbound.put(["send", [soc, header + payload]])
    elif command == "send":
        msg, pub_key = cargo
        msg = msg.encode("utf-8").hex()
        payload = blockchain.create_tx(msg, pub_key)
        blockchain.mempool.append(payload.hex())
        payload_lenght = hex(len(payload))[2:]
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
        blockchain.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        block_header = blockchain.c.fetchone()[0]
        payload = bytes.fromhex(block_header + "0"*64)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("getheaders", payload_lenght)
        outbound.put(["send", [soc, header + payload]])
    elif command == "addr":
        if cargo == "init":
            payload = bytes.fromhex("0001" + encode_ip(my_addr) + fill(hex(port)[2:], 4) + hex(int(time()))[2:])
        elif cargo != None:
            payload = cargo
        else:
            timestamp = int(time()) - 18000
            c.execute("SELECT * FROM nodes WHERE timestamp > ?;", ())
            if c.fetchall() == []:
                return
            ls_nodes = c.fetchall()
            num_addr = 0
            payload = ""
            for node in ls_nodes:
                peer = soc.getpeername()
                if node[0] != peer[0] and node[1] != peer[1]:
                    num_addr += 1
                    payload = encode_ip(node[0]) + fill(hex(node[1])[2:], 4) + hex(node[2])[2:]
                if num_addr == 1000:
                    break
            payload = bytes.fromhex(fill(hex(num_addr)[2:], 4) + payload)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("addr", payload_lenght)
        if cargo == "broacast":
            outbound.put(["broadcast", [soc, header + payload]])
        else:
            outbound.put(["send", [soc, header + payload]])
    elif command == "only":
        header = create_header(cargo, "0")
        outbound.put(["send", [soc, header]])


def create_header(command, payload_lenght):
    return bytes.fromhex(fill(command.encode("utf-8").hex(), 24) + fill(payload_lenght, 8))


def fill(entity, fill):
    lenght = len(entity)
    if lenght < fill:
        miss = fill - lenght
        entity = miss*"0" + entity
    return entity


def encode_ip(ip):
    ip = ip.split(".")
    addr = ""
    for i in ip:
        if 0 > int(i) > 255:
            print("neplatna adresa")
            return
        temp = hex(int(i))[2:]
        addr += fill(temp, 2)
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
    nodes[address].banscore += 1
    if nodes[address].banscore >= 10:
        outbound.put(["close", list(nodes[address].address])


def connect():
    global nodes, con_sent, c
    node_list = [(i.address[0], i.port) for i in list(nodes.keys())]
    print(node_list)
    while True:
        c.execute("SELECT * FROM table ORDER BY RANDOM() LIMIT 1")
        query = c.fetchone()#bude cakat kym dostanem addr od con aby som dostal nove adresy!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        line = tuple(query[0], query[1])
        if line not in node_list:
            outbound.put(["connect", [i[0], send_message("version1", cargo=i[1])]])
            con_sent = True
            break


version = "00000001"
stime = int(time())
nodes = {}
expec_blocks = 0
opt_nodes = 5
num_time = 0
my_addr = ""
port = 55555
default_port = 55555
con_sent = False
hadcoded_nodes = (("192.168.1.101", 55555),)
inbound = Queue()
outbound = Queue()
to_mine = Queue()
mined = Queue()
com = Queue()
prnt = Queue()
display = Queue()
sync = True
conn = sqlite3.connect("nodes.db")
c = conn.cursor()
blockchain = Blockchain(version,prnt)
local_node = threading.Thread(target=p2p.start_node, args=(port, nodes, inbound, outbound))
local_node.start()
tcli = threading.Thread(target=cli, args=(com, display, prnt))
tcli.start()

c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='blockchain'")
if c.fetchone()[0] != 1:
    c.execute("""CREATE TABLE nodes (
        addr TEXT,
        port INTEGER)
        timestamp INTEGER
        """)

print("finding nodes...")
c.execute("SELECT * FROM nodes;")
if c.fetchall() == []:
    for i in hadcoded_nodes:
        sent = None
        outbound.put(["connect", [i[0], i[1], send_message("version1", cargo=i[0])]])
        started = int(time())
        while True:
            if not inbound.empty():
                soc, message = inbound.get()
                if message == "error":
                    break
                handle_message(soc, message)
                if message == "00000000006765746164647200000000":
                    break
            if int(time()) - started > 120:
                break
        outbound.put(["close", list(nodes.values())[0].address])
        c.execute("SELECT * FROM nodes;")
        if len(c.fetchall()) >= 8:
            break#treba zatvorit conection
print("connecting...")

while True:
    if len(nodes) < opt_nodes:
        if len(nodes) == 0:
            print("connecting...")
        if not con_sent:
            connect()#mozno by bolo lepsie spravit init connect v loope pred tymto
    if not inbound.empty():
        soc, message = inbound.get()
        if message == "error":
            c.execute("DELETE FROM nodes WHERE addr=(?) AND port=(?)", (soc[1], soc[2]))
            conn.commit()
            con_sent = False
        else:
            handle_message(soc, message)
    if not mined.empty():
        new_block = mined.get()
        print(new_block)
        new_block_hash = blockchain.hash(new_block[:216])
        blockchain.append(new_block)
        send_message("broadcast", cargo=["01"+new_block_hash, "headers"])
        block_header, txs = blockchain.build_block()
        to_mine.put([block_header, txs])
    if int(time()) - stime > 1800:
        num_time += 1
        current_time = int(time())
        for i in list(nodes.values()):
            c.execute("UPDATE nodes timestamp = (?) WHERE addr = (?) AND port = (?);", (i.lastrecv, i.address[0], i.address[1]))
            if current_time - i.lastsend < 1800:
                send_message("only", soc=nodes[soc.getpeername()].socket, cargo="active")
            if current_time - i.lastrecv < 5400:
                outbound.put(["close", i.address])
        if num_time == 48:
            send_message("addr", cargo="broadcast")
            c.execute("SELECT MAX(rowid) FROM nodes;")
            rowid = c.fetchone()[0]
            if len(nodes) >= 3 and rowid > 1000:
                c.execute("DELETE FROM nodes WHERE timestamp<(?)", (stime, ))
                num_time = 0
            stime = int(time())
        conn.commit()
    if not com.empty():
        a, b = com.get()
        if a == "con":
            b, c = b
            outbound.put(["connect", [b, c, send_message("version1", cargo=b)]])
        elif a == "send":
            b,c = b
            if b == "":
                display.put(list(blockchain.pub_keys.values()))
            else:
                cargo = [c, list(blockchain.pub_keys.keys())[b]]
                send_message("send", cargo=cargo)
        elif a == "import":
            b, c = b
            blockchain.save_key(b, c)
        elif a == "export":
            display.put(blockchain.ver_key_str)
        elif a == "lsimported":
            display.put(blockchain.pub_keys)
        elif a == "lsnodes":
            display.put(list(nodes.values()))
        elif a == "start mining":
            block_header, txs = blockchain.build_block()
            to_mine.put([block_header, txs])
            mining = threading.Thread(target=mine, args=(mined, to_mine))
            mining.start()
        elif a == "stop mining":
            if mining:
                mining.terminate()
                mining = None
        elif a == "sync":
            if b == "":
                display.put(list(nodes.values()))
            else:
                sync = False
                sock = list(nodes.values())[b].socket
                send_message("sync", soc=sock)
        elif a == "highest":
            blockchain.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
            print(blockchain.c.fetchone()[1])
        elif a == "end":
            #print(mining)
            outbound.put(["end", []])
            local_node.join()
            #if mining:
                #mining.terminate()
            break
