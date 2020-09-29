import socket
import select
import sqlite3
import hashlib
import threading
from time import time
from multiprocessing import Queue, Process
from ecdsa import SigningKey, VerifyingKey, SECP256k1

import p2p
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
                        print(msg)
                else:
                    pass


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
        payload = bytes.fromhex(payload)
        payload_lenght = hex(len(payload))[2:]
        header = create_header(type, payload_lenght)
        outbound.put(["broadcast", [soc, header + payload]])


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
local_node = threading.Thread(target=p2p.start_node, args=(nodes, inbound, outbound))
local_node.start()

while True:
    if not inbound.empty():
        soc, message = inbound.get()
        handle_message(soc, message)
    if not mined.empty():
        new_block = mined.get()
        new_block_hash = blockchain.hash(new_block[:216])
        send_message("broadcast", cargo=[new_block_hash, "header"])
        blockchain.c.execute("INSERT INTO blockchain VALUES (?,?);", (new_block_hash, new_block))
        blockchain.conn.commit()
        block_header, txs = blockchain.build_block()
        to_mine.put([block_header, txs])

    a = input("zadaj daco: ")
    if a == "con":
        b = input("zadaj adresu: ")
        outbound.put(["connect", [b, send_message("version1")]])
    elif a == "send":
        for i in list(blockchain.pub_keys.values()):
            print(i)
        b = int(input("zadaj cislo mena(0-n): "))
        c = input("zadaj spravu: ")
        cargo = [c, list(blockchain.pub_keys.keys())[b]]
        send_message("send", cargo=cargo)
    elif a == "import":
        b = input("zadaj kluc: ")
        c = input("zadaj meno: ")
        blockchain.save_key(b, c)
    elif a == "export":
        print(blockchain.ver_key_str)
    elif a == "lsimported":
        for i in blockchain.pub_keys:
            print(f"{blockchain.pub_keys[i]}: {i}")
    elif a == "lsnodes":
        for i in nodes.values():
            print(f"{i.address}: {i.authorized}")
    elif a == "start mining":
        block_header, txs = blockchain.build_block()
        to_mine.put([block_header, txs])
        mining = threading.Thread(target=mine, args=(mined, to_mine))
        mining.start()
    elif a == "stop mining":
        if mining:
            mining.terminate()
            mining = None
    elif a == "help":
        print("\ncon\nsend\nimport\nexport\nlsimported\nlsnodes\nstart mining\nstop mining\nend\n")
    elif a == "end":
        print(mining)
        outbound.put(["end", []])
        local_node.join()
        #if mining:
            #mining.terminate()
        break
