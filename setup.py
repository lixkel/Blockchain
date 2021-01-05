import socket
import select
import sqlite3
import hashlib
import logging
import threading
import traceback
from time import time
from random import randint
from multiprocessing import Queue, Process

import p2p
from cli import cli
from node import node
from proof_of_work import mine
from blockchain import Blockchain

version = "00000001"
stime = int(time())
nodes = {}
mining = None
expec_blocks = 0
opt_nodes = 5
num_time = 0
my_addr = ""
prev_time = int(time())
port = 55555#bude treba otestovat minenie zaroven a prechod na alter chain pod aj nad 255 blockov
default_port = 55555
con_sent = False
hardcoded_nodes = (("146.59.15.193", 55555),)
inbound = Queue()
outbound = Queue()
to_mine = Queue()
mined = Queue()
com = Queue()
prnt = Queue()
display = Queue()
ban_list = []
sync = [True, 0, None]#[synced, time of sending, nodes address]
conn = sqlite3.connect("nodes.db")
c = conn.cursor()
logging.basicConfig(filename='blockchain.log', level=logging.DEBUG, format='%(threadName)s: %(asctime)s %(message)s', filemode="w")
local_node = threading.Thread(target=p2p.start_node, args=(port, nodes, inbound, outbound, ban_list, logging))
tcli = threading.Thread(target=cli, args=(com, display, prnt))
