from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import sqlite3
import json
import secrets
import base64
from datetime import datetime
import os


class TimestampService:
    def __init__(self, db_path='server.db', key_size=2048):
        self.db_path = db_path
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        # ensure timestamps table exists and load/create key
        self._ensure_tables()
        self._load_or_create_key()

    def _ensure_tables(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS tsa_keys (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                tsa_priv_key_pem BLOB,
                tsa_pub_key_pem BLOB
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS timestamps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_hash TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def _load_or_create_key(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT tsa_priv_key_pem, tsa_pub_key_pem FROM tsa_keys WHERE id=1')
        row = c.fetchone()
        if row and row[0] and row[1]:
            priv_pem, pub_pem = row
            self.private_key = serialization.load_pem_private_key(
                priv_pem,
                password=None,
                backend=default_backend()
            )
            self.public_key = serialization.load_pem_public_key(
                pub_pem,
                backend=default_backend()
            )
        else:
            # generate a new RSA keypair for TSA
            priv = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            pub = priv.public_key()

            priv_pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            c.execute('INSERT OR REPLACE INTO tsa_keys (id, tsa_priv_key_pem, tsa_pub_key_pem) VALUES (1, ?, ?)',
                      (priv_pem, pub_pem))
            conn.commit()

            self.private_key = priv
            self.public_key = pub

        conn.close()

    def issue_timestamp(self, item_hash, action='issue_token', client_time=None):
        # Issue a signed timestamp for `item_hash`.
        # Returns a dict with: id, payload (dict), signature (base64 string)

        nonce = secrets.token_hex(16)
        if client_time is None:
            client_time = datetime.utcnow().isoformat() + 'Z'
        tsa_time = datetime.utcnow().isoformat() + 'Z'

        payload = {
            'item': item_hash,
            'action': action,
            'client_time': client_time,
            'tsa_time': tsa_time,
            'nonce': nonce,
            'kid': 'tsa-v1'
        }

        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

        signature = self.private_key.sign(
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # store in DB
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('INSERT INTO timestamps (item_hash, payload, signature) VALUES (?, ?, ?)',
                  (item_hash, payload_bytes, signature))
        conn.commit()
        ts_id = c.lastrowid
        conn.close()

        return {
            'id': ts_id,
            'payload': payload,
            'signature': base64.b64encode(signature).decode('ascii')
        }


if __name__ == '__main__':
    # quick demo
    proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dbp = os.path.join(proj_root, 'server.db')
    tsa = TimestampService(db_path=dbp)
    r = tsa.issue_timestamp('demo-item-' + secrets.token_hex(4))
    print('Issued timestamp:', r)
