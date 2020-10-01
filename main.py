import socket
import select
import sqlite3
import hashlib
import threading
from time import time
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
    command = bytes.fromhex(message[:24].lstrip("0")).decode("utf-8")
    payload = message[32:]
    if command == "version":
        if nodes[soc.getpeername()].expecting == "version":
            node_version = payload[:8]
            if node_version != version:
                return
            timestamp = int(payload[8:24], 16)
            time_difference = int(int(time()) - timestamp)
            if -300 < time_difference > 300:
                return
            if nodes[soc.getpeername()].connection == "inbound":
                send_message("version", nodes[soc.getpeername()].socket)
                nodes[soc.getpeername()].expecting = "verack"
            else:
                send_message("verack", nodes[soc.getpeername()].socket)
                nodes[soc.getpeername()].authorized = True
                nodes[soc.getpeername()].expecting = ""
    elif command == "verack":
        if nodes[soc.getpeername()].expecting == "verack":
            nodes[soc.getpeername()].authorized = True
            nodes[soc.getpeername()].expecting = ""
    elif command == "transaction":
        if nodes[soc.getpeername()].authorized == True:
            if blockchain.verify_tx(payload) == True:
                if payload not in blockchain.mempool:
                    blockchain.mempool.append(payload)
                    send_message("broadcast", soc=soc, cargo=[payload, "transaction"])
                    msg = blockchain.tx_content(payload)
                    if msg:
                        prnt.put(msg)
                else:
                    pass
    elif command == "headers":
        num_headers = int(payload[:4],16)
        index = 4
        #toto je docasne este presne neviem ako idem robit sync
        for i in range(num_headers):
            header_hash = payload[index:index+64]
            print(header_hash)
            blockchain.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (header_hash,))
            result = blockchain.c.fetchone()
            if result == None and i % 127 == 0:
                getblocks += header_hash
                if i == 127:
                    break
        if len(getblocks) == 64:
            getblocks += getblocks
        send_message("getblocks", soc=soc, cargo=getblocks)
    elif command == "getblocks":
        if payload[:64] == payload[64:]:
            header_hash = payload[:64]
            print(header_hash)
            blockchain.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (header_hash,))
            result = blockchain.c.fetchone()
            block = result[1]
            send_message("block", soc=soc, cargo=block)
        else:
            prnt.put("dojebana picovina")
    elif command == "block":
        prnt.put(payload)


def send_message(command, soc = None, cargo = None):
    global version
    global nodes
    if command == "version" or command == "version1":
        timestamp = hex(int(time()))[2:]
        payload = bytes.fromhex(version + timestamp)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("version", payload_lenght)
        if command == "version1":
            return header + payload
        outbound.put(["send", [soc, header + payload]])
    elif command == "verack":
        header = create_header(command, "0")
        outbound.put(["send", [soc, header]])
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
        if type == "headers":
            payload = "0001" + payload
        payload = bytes.fromhex(payload)
        payload_lenght = hex(len(payload))[2:]
        header = create_header(type, payload_lenght)
        outbound.put(["broadcast", [soc, header + payload]])
    elif command == "getblocks":
        payload = bytes.fromhex(cargo)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("getblocks", payload_lenght)
        outbound.put(["send", [soc, header + payload]])
    elif command == "block":
        payload = bytes.fromhex(cargo)
        payload_lenght = hex(len(payload))[2:]
        header = create_header("block", payload_lenght)
        outbound.put(["send", [soc, header + payload]])


def create_header(command, payload_lenght):
    return fill(command.encode("utf-8").hex(), 24) + fill(payload_lenght, 8)


def fill(entity, fill):
    lenght = len(entity)
    if lenght < fill:
        miss = fill - lenght
        entity = miss*"0" + entity
    return bytes.fromhex(entity)


version = "00000001"
blockchain = Blockchain(version)
nodes = {}
inbound = Queue()
outbound = Queue()
to_mine = Queue()
mined = Queue()
com = Queue()
prnt = Queue()
display = Queue()
local_node = threading.Thread(target=p2p.start_node, args=(nodes, inbound, outbound))
local_node.start()
tcli = threading.Thread(target=cli, args=(com, display, prnt))
tcli.start()

while True:
    if not inbound.empty():
        soc, message = inbound.get()
        handle_message(soc, message)
    if not mined.empty():
        new_block = mined.get()
        new_block_hash = blockchain.hash(new_block[:216])
        send_message("broadcast", cargo=[new_block_hash, "headers"])
        blockchain.c.execute("INSERT INTO blockchain VALUES (?,?);", (new_block_hash, new_block))
        blockchain.conn.commit()
        block_header, txs = blockchain.build_block()
        to_mine.put([block_header, txs])
    if not com.empty():
        a, b = com.get()
        if a == "con":
            outbound.put(["connect", [b, send_message("version1")]])
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
        elif a == "end":
            #print(mining)
            outbound.put(["end", []])
            local_node.join()
            #if mining:
                #mining.terminate()
            break
