"""
Servidor Central do Sistema de Leilões P2P
Todas as chaves guardadas na BD
"""

import asyncio
from crypto.cert_auth import AuctionCA
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from crypto.cert_auth import AuctionCA
from crypto.blind_signature import BlindSignature

DB_PATH = 'server.db'
SERVER_CERT_PEM = None          # Certificado da CA (público)
SERVER_PRIV_KEY = None          # Chave privada da CA (secreta)
SERVER_BLIND_PRIV_KEY = None    # Chave privada para blind signatures
SERVER_BLIND_PUB_KEY = None     # Chave pública para blind signatures
CA = None                        # Objeto AuctionCA
BLIND_SIG = None                 # Objeto BlindSignature

def init_db():

    #check if server db exists, if not create it
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    #tabela vai possuir: id, username, pub_key_pem, anonymous_tokens, user_Acess p2p

    #execute de drop para teste
    # c.execute('DROP TABLE IF EXISTS users')
    # c.execute('DROP TABLE IF EXISTS anonymous_tokens')
    # c.execute('DROP TABLE IF EXISTS ca_certs')
    # c.execute('DROP TABLE IF EXISTS blind_signature_keys')

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
    #tabela certificados da CA
    c.execute ('''
               CREATE TABLE IF NOT EXISTS ca_certs (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    ca_cert_pem BLOB,
                    ca_priv_key_pem BLOB
                )
        ''')
    #tabela chave blind 
    c.execute ('''
               CREATE TABLE IF NOT EXISTS blind_signature_keys (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    blind_priv_key_pem BLOB,
                    blind_pub_key_pem BLOB
                )
        ''')
    conn.commit()
    conn.close()

def init_auction_ca():
    # allow assigning to module-level globals
    global SERVER_CERT_PEM, SERVER_PRIV_KEY

    #check database for existing CA cert and key
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute ('SELECT ca_cert_pem, ca_priv_key_pem FROM ca_certs WHERE id=1')
    row = c.fetchone()

    if row and row[0] and row[1]:
        ca_cert_pem, ca_key_pem = row
        SERVER_CERT_PEM = ca_cert_pem
        SERVER_PRIV_KEY = ca_key_pem
        ca = AuctionCA(ca_key_pem=ca_key_pem , ca_cert_pem=ca_cert_pem)  
    else:
        ca = AuctionCA()
        #store the PEMs in the database
        ca_cert_pem = ca.ca_cert.public_bytes(serialization.Encoding.PEM)
        SERVER_CERT_PEM = ca_cert_pem
        SERVER_PRIV_KEY = ca.ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        c.execute('INSERT OR REPLACE INTO ca_certs (id, ca_cert_pem, ca_priv_key_pem) VALUES (1, ?, ?)',
                  (ca_cert_pem, SERVER_PRIV_KEY))
        conn.commit()
    conn.close()
    return ca
    
def init_blind_signature_keys():
    """Inicializa as chaves separadas para blind signatures"""

    global SERVER_BLIND_PRIV_KEY, SERVER_BLIND_PUB_KEY, BLIND_SIG

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT blind_priv_key_pem, blind_pub_key_pem FROM blind_signature_keys WHERE id=1')
    row = c.fetchone()
    if row and row[0] and row[1]:
        blind_priv_key_pem, blind_pub_key_pem = row
        SERVER_BLIND_PRIV_KEY = serialization.load_pem_private_key(
            blind_priv_key_pem,
            password=None,
            backend=default_backend()
        )
        SERVER_BLIND_PUB_KEY = serialization.load_pem_public_key(
            blind_pub_key_pem,
            backend=default_backend()
        )
        print("Blind signature keys loaded from database.")
    else:
        # Chaves não existem - gerar novas
        print("  ↪ Generating new blind signature keys...")
        
        SERVER_BLIND_PRIV_KEY = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # 2048 para dev, 4096 para produção
            backend=default_backend()
        )
        SERVER_BLIND_PUB_KEY = SERVER_BLIND_PRIV_KEY.public_key()
        
        # Serializar
        pub_key_pem = SERVER_BLIND_PUB_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        priv_key_pem = SERVER_BLIND_PRIV_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Guardar na BD
        c.execute(
            'INSERT OR REPLACE INTO blind_signature_keys (id, blind_priv_key_pem, blind_pub_key_pem) VALUES (1, ?, ?)',
            (priv_key_pem, pub_key_pem)
        )
        conn.commit()
        
        print("  ✓ Blind signature keys generated and stored in database")
    
    conn.close()
    
    # Inicializar handler de blind signatures
    BLIND_SIG = BlindSignature()
    print("  ✓ Blind signature handler ready")

    
async def message_handler():
    """Handler assíncrono para mensagens dos clientes"""
    
    

def run_server():
    """Inicializa e corre o servidor de leilões"""


    try:
        loop = asyncio.get_event_loop()
        init_db()
        ca = init_auction_ca()
        init_blind_signature_keys()
        print("Server initialized successfully.")
        print("Auction CA Certificate:\n", SERVER_CERT_PEM[:120], "...")
        print("Auction Server priv key:\n", SERVER_PRIV_KEY[:120], "...")
    except Exception as e:
        print(f"Error initializing server: {e}")
        return



if __name__ == "__main__":
    run_server()