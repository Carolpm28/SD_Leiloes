import asyncio
from crypto.cert_auth import AuctionCA
import sqlite3
from cryptography.hazmat.primitives import hashes, serialization



def init_db():

    #check if server db exists, if not create it
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    #tabela vai possuir: id, username, pub_key_pem, anonymous_tokens, user_Acess p2p
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL
        )
    ''')
    #tabela tokens anonimos
    c.execute ('''
            CREATE TABLE IF NOT EXISTS anonymous_tokens (
                token_hash TEXT PRIMARY KEY,
                used INTEGER DEFAULT 0,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP
            )
        ''')
    c.execute ('''
               CREATE TABLE IF NOT EXISTS ca_certs (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    ca_cert_pem BLOB,
                    ca_priv_key_pem BLOB
                )
        ''')
    conn.commit()
    conn.close()

def init_auction_ca():
    init_db()
    #check database for existing CA cert and key
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute ('SELECT ca_cert_pem, ca_priv_key_pem FROM ca_certs WHERE id=1')
    row = c.fetchone()

    if row and row[0] and row[1]:
        ca_cert_pem, ca_key_pem = row
        ca = AuctionCA(ca_cert_pem=ca_cert_pem, ca_key_pem=ca_key_pem)  
    else:
        ca = AuctionCA()
        #store the PEMs in the database
        ca_cert_pem = ca.ca_cert.public_bytes(serialization.Encoding.PEM)
        ca_key_pem = ca.ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        c.execute('INSERT OR REPLACE INTO ca_certs (id, ca_cert_pem, ca_priv_key_pem) VALUES (1, ?, ?)',
                  (ca_cert_pem, ca_key_pem))
        conn.commit()
    conn.close()
    return ca
    



def run_server():
    loop = asyncio.get_event_loop()
    ca = init_auction_ca()
    