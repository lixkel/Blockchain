import sqlite3
from time import time
import hashlib


class Blockchain:
    def __init__(self):
        self.conn = sqlite3.connect("blockchain.db")
        self.c = self.conn.cursor()
        self.mempool = []
        try:
            self.c.execute("SELECT * FROM blockhain")
        except:
            c.execute("""CREATE TABLE test (
                hash text,
                block text)
                """)
