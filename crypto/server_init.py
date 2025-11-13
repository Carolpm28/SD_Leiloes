import os
import sqlite3
import asyncio
from crypto.cert_auth import AuctionCA
from crypto.keys import KeyManager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Globals populated at init
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
SERVER_CERT_PEM = None


def init_db(db_path: str = 'server.db'):
    """Create required tables if not present."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # tabela users
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL
        )
    ''')
    # tabela tokens anonimos
    c.execute('''
        CREATE TABLE IF NOT EXISTS anonymous_tokens (
            token_hash TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP
        )
    ''')
    # tabela para CA pem/key
    c.execute('''
        CREATE TABLE IF NOT EXISTS auction_ca (
            id INTEGER PRIMARY KEY,
            ca_cert_pem BLOB,
            ca_key_pem BLOB
        )
    ''')
    # tabela para server keys/cert
    c.execute('''
        CREATE TABLE IF NOT EXISTS server_keys (
            id INTEGER PRIMARY KEY,
            server_key_pem BLOB,
            server_cert_pem BLOB
        )
    ''')
    conn.commit()
    conn.close()


def init_auction_ca(db_path: str = 'server.db') -> AuctionCA:
    """Load or create the Auction CA and persist its PEMs in the DB.

    Returns: AuctionCA instance
    """
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT ca_cert_pem, ca_key_pem FROM auction_ca WHERE id=1')
    row = c.fetchone()

    if row and row[0] and row[1]:
        ca_cert_pem, ca_key_pem = row
        # write PEMs to disk so AuctionCA can load them (keeps existing API)
        with open('ca_cert.pem', 'wb') as f:
            f.write(ca_cert_pem)
        with open('ca_private.pem', 'wb') as f:
            f.write(ca_key_pem)
        ca = AuctionCA(ca_key_path='ca_private.pem', ca_cert_path='ca_cert.pem')
        conn.close()
        return ca

    # Not present in DB -> create new CA (AuctionCA will write files)
    ca = AuctionCA(ca_key_path='ca_private.pem', ca_cert_path='ca_cert.pem')

    # read generated files and persist into DB
    with open('ca_cert.pem', 'rb') as f:
        ca_cert_bytes = f.read()
    with open('ca_private.pem', 'rb') as f:
        ca_key_bytes = f.read()

    c.execute('DELETE FROM auction_ca WHERE id=1')
    c.execute('INSERT INTO auction_ca (id, ca_cert_pem, ca_key_pem) VALUES (1, ?, ?)',
              (ca_cert_bytes, ca_key_bytes))
    conn.commit()
    conn.close()
    return ca


def init_server_keys(db_path: str = 'server.db'):
    """Inicializar chaves do servidor a partir da base de dados.

    Se existirem, carrega a chave privada PEM e o certificado PEM da tabela `server_keys`.
    Se não existirem, gera um novo par RSA (usando KeyManager), pede à CA um certificado
    para a chave pública do servidor e persiste ambos no DB.

    Globals populados: SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, SERVER_CERT_PEM
    """
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, SERVER_CERT_PEM

    init_db(db_path)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT server_key_pem, server_cert_pem FROM server_keys WHERE id=1')
    row = c.fetchone()

    if row and row[0] and row[1]:
        key_pem, cert_pem = row
        # load private key from PEM bytes
        SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )
        # load cert public key
        SERVER_CERT_PEM = cert_pem.decode('utf-8') if isinstance(cert_pem, (bytes, bytearray)) else cert_pem
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        SERVER_PUBLIC_KEY = cert.public_key()

        conn.close()
        print("✓ Loaded server private key and certificate from DB")
        return

    # Not found -> generate new keypair and request a cert from CA
    km = KeyManager(key_size=2048)
    priv, pub = km.generate_rsa_keypair()

    # Ensure CA exists
    ca = init_auction_ca(db_path)

    # Ask CA to issue certificate for this server
    # Use user_id 'server' and username 'auction-server'
    cert_pem = ca.issue_certificate("server", "auction-server", pub, validity_days=3650)

    # Serialize private key to PEM
    key_pem_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    cert_pem_bytes = cert_pem.encode('utf-8') if isinstance(cert_pem, str) else cert_pem

    # Persist to DB
    c.execute('DELETE FROM server_keys WHERE id=1')
    c.execute('INSERT INTO server_keys (id, server_key_pem, server_cert_pem) VALUES (1, ?, ?)',
              (key_pem_bytes, cert_pem_bytes))
    conn.commit()
    conn.close()

    # Populate globals
    SERVER_PRIVATE_KEY = priv
    SERVER_PUBLIC_KEY = pub
    SERVER_CERT_PEM = cert_pem if isinstance(cert_pem, str) else cert_pem.decode('utf-8')

    # Optionally write to disk for tooling
    try:
        with open('server_private.pem', 'wb') as f:
            f.write(key_pem_bytes)
        with open('server_cert.pem', 'wb') as f:
            f.write(cert_pem_bytes)
    except Exception:
        pass

    print("✓ Generated new server keypair and certificate and stored in DB")


if __name__ == '__main__':
    # quick demo: initialize and print whether loaded/generated
    ca = init_auction_ca()
    init_server_keys()
    print('Server cert PEM (truncated):')
    if SERVER_CERT_PEM:
        print(SERVER_CERT_PEM[:200])
