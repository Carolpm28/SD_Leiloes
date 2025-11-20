"""
Servidor Central do Sistema de Leilões P2P
Todas as chaves guardadas na BD
"""

import asyncio
import json
import sqlite3
from datetime import datetime
from crypto.cert_auth import AuctionCA
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from crypto.blind_signature import BlindSignature

DB_PATH = 'server.db'
SERVER_CERT_PEM = None
SERVER_PRIV_KEY = None
SERVER_BLIND_PRIV_KEY = None
SERVER_BLIND_PUB_KEY = None
CA = None
BLIND_SIG = None

# Configuração do servidor
SERVER_HOST = '0.0.0.0'  # Aceita conexões de qualquer interface
SERVER_PORT = 9999

def init_db():
    """Inicializa a base de dados"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS anonymous_tokens (
            token_hash TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS ca_certs (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            ca_cert_pem BLOB,
            ca_priv_key_pem BLOB
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS blind_signature_keys (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            blind_priv_key_pem BLOB,
            blind_pub_key_pem BLOB
        )
    ''')
    
    conn.commit()
    conn.close()

def init_auction_ca():
    """Inicializa a CA do sistema"""
    global SERVER_CERT_PEM, SERVER_PRIV_KEY, CA
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ca_cert_pem, ca_priv_key_pem FROM ca_certs WHERE id=1')
    row = c.fetchone()
    
    if row and row[0] and row[1]:
        ca_cert_pem, ca_key_pem = row
        SERVER_CERT_PEM = ca_cert_pem
        SERVER_PRIV_KEY = ca_key_pem
        ca = AuctionCA(ca_key_pem=ca_key_pem, ca_cert_pem=ca_cert_pem)
    else:
        ca = AuctionCA()
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
    CA = ca
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
        print("✓ Blind signature keys loaded from database")
    else:
        print("↪ Generating new blind signature keys...")
        
        SERVER_BLIND_PRIV_KEY = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        SERVER_BLIND_PUB_KEY = SERVER_BLIND_PRIV_KEY.public_key()
        
        pub_key_pem = SERVER_BLIND_PUB_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        priv_key_pem = SERVER_BLIND_PRIV_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        c.execute(
            'INSERT OR REPLACE INTO blind_signature_keys (id, blind_priv_key_pem, blind_pub_key_pem) VALUES (1, ?, ?)',
            (priv_key_pem, pub_key_pem)
        )
        conn.commit()
        print("✓ Blind signature keys generated and stored")
    
    conn.close()
    BLIND_SIG = BlindSignature()
    print("✓ Blind signature handler ready")


# ============================================================================
# HANDLERS DAS MENSAGENS
# ============================================================================

async def handle_register(data, writer):
    """Processa pedido de registo de novo utilizador"""
    try:
        username = data['username']
        pub_key_pem = data['public_key']
        ip = data['ip']
        port = data['port']
        
        # Gerar user_id (hash da chave pública)
        from cryptography.hazmat.primitives import hashes
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pub_key_pem.encode())
        user_id = digest.finalize().hex()[:16]
        
        # Guardar na BD
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO users (user_id, username, public_key, ip, port)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, username, pub_key_pem, ip, port))
        conn.commit()
        conn.close()
        
        # Emitir certificado X.509
        cert_pem = CA.issue_certificate(username, pub_key_pem)
        
        response = {
            'status': 'success',
            'user_id': user_id,
            'certificate': cert_pem.decode(),
            'ca_certificate': SERVER_CERT_PEM.decode()
        }
        
        print(f"✓ Registered user: {username} (ID: {user_id})")
        
    except sqlite3.IntegrityError:
        response = {'status': 'error', 'message': 'Username already exists'}
    except Exception as e:
        response = {'status': 'error', 'message': str(e)}
    
    return response


async def handle_get_blind_token(data, writer):
    """Processa pedido de token cego para anonimato"""
    try:
        blinded_message = data['blinded_message']
        
        # Assinar mensagem cega
        blind_signature = BLIND_SIG.sign_blinded_message(
            blinded_message,
            SERVER_BLIND_PRIV_KEY
        )
        
        # Guardar hash do token na BD (para evitar reutilização)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(blinded_message.encode())
        token_hash = digest.finalize().hex()
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO anonymous_tokens (token_hash, used)
            VALUES (?, 0)
        ''', (token_hash,))
        conn.commit()
        conn.close()
        
        response = {
            'status': 'success',
            'blind_signature': blind_signature,
            'blind_public_key': SERVER_BLIND_PUB_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        
        print(f"✓ Issued blind token (hash: {token_hash[:16]}...)")
        
    except Exception as e:
        response = {'status': 'error', 'message': str(e)}
    
    return response


async def handle_verify_token(data, writer):
    """Verifica se um token anónimo é válido e não foi usado"""
    try:
        token_hash = data['token_hash']
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT used FROM anonymous_tokens WHERE token_hash = ?', (token_hash,))
        row = c.fetchone()
        
        if not row:
            response = {'status': 'error', 'message': 'Token not found'}
        elif row[0] == 1:
            response = {'status': 'error', 'message': 'Token already used'}
        else:
            # Marcar token como usado
            c.execute('''
                UPDATE anonymous_tokens 
                SET used = 1, used_at = ? 
                WHERE token_hash = ?
            ''', (datetime.now().isoformat(), token_hash))
            conn.commit()
            response = {'status': 'success', 'message': 'Token valid'}
        
        conn.close()
        
    except Exception as e:
        response = {'status': 'error', 'message': str(e)}
    
    return response


async def handle_get_users(data, writer):
    """Retorna lista de utilizadores registados (para descoberta P2P)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT user_id, username, ip, port FROM users')
        rows = c.fetchall()
        conn.close()
        
        users = [
            {'user_id': row[0], 'username': row[1], 'ip': row[2], 'port': row[3]}
            for row in rows
        ]
        
        response = {
            'status': 'success',
            'users': users
        }
        
    except Exception as e:
        response = {'status': 'error', 'message': str(e)}
    
    return response


async def handle_timestamp(data, writer):
    """Gera timestamp confiável para um lance"""
    try:
        bid_data = data['bid_data']
        
        # Criar timestamp assinado
        timestamp = datetime.now().isoformat()
        timestamp_message = f"{bid_data}|{timestamp}"
        
        # Assinar com chave privada da CA
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = SERVER_PRIV_KEY.sign(
            timestamp_message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        response = {
            'status': 'success',
            'timestamp': timestamp,
            'signature': signature.hex()
        }
        
        print(f"✓ Issued timestamp: {timestamp}")
        
    except Exception as e:
        response = {'status': 'error', 'message': str(e)}
    
    return response


# ============================================================================
# SERVIDOR ASSÍNCRONO
# ============================================================================

async def handle_client(reader, writer):
    """Handler principal para cada conexão de cliente"""
    addr = writer.get_extra_info('peername')
    print(f"→ New connection from {addr}")
    
    try:
        # Ler dados do cliente
        data_bytes = await reader.read(65536)  # 64KB buffer
        
        if not data_bytes:
            print(f"✗ Empty request from {addr}")
            return
        
        # Parse JSON
        message = json.loads(data_bytes.decode())
        action = message.get('action')
        
        print(f"  Action: {action}")
        
        # Routing das mensagens
        if action == 'register':
            response = await handle_register(message, writer)
        elif action == 'get_blind_token':
            response = await handle_get_blind_token(message, writer)
        elif action == 'verify_token':
            response = await handle_verify_token(message, writer)
        elif action == 'get_users':
            response = await handle_get_users(message, writer)
        elif action == 'timestamp':
            response = await handle_timestamp(message, writer)
        else:
            response = {'status': 'error', 'message': f'Unknown action: {action}'}
        
        # Enviar resposta
        response_json = json.dumps(response)
        writer.write(response_json.encode())
        await writer.drain()
        
        print(f"✓ Response sent to {addr}")
        
    except json.JSONDecodeError:
        print(f"✗ Invalid JSON from {addr}")
        error_response = json.dumps({'status': 'error', 'message': 'Invalid JSON'})
        writer.write(error_response.encode())
        await writer.drain()
    
    except Exception as e:
        print(f"✗ Error handling client {addr}: {e}")
        error_response = json.dumps({'status': 'error', 'message': str(e)})
        writer.write(error_response.encode())
        await writer.drain()
    
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"← Connection closed: {addr}")


async def main():
    """Função principal do servidor"""
    print("=" * 60)
    print("SERVIDOR DE LEILÕES P2P")
    print("=" * 60)
    
    # Inicializar componentes
    print("\n[1/3] Initializing database...")
    init_db()
    
    print("[2/3] Initializing Certificate Authority...")
    init_auction_ca()
    
    print("[3/3] Initializing Blind Signature system...")
    init_blind_signature_keys()
    
    print("\n" + "=" * 60)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 60 + "\n")
    
    # Criar servidor TCP
    server = await asyncio.start_server(
        handle_client,
        SERVER_HOST,
        SERVER_PORT
    )
    
    # Manter servidor a correr
    async with server:
        await server.serve_forever()


def run_server():
    """Entry point do servidor"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n✓ Server shutdown requested")
    except Exception as e:
        print(f"\n✗ Server error: {e}")


if __name__ == "__main__":
    run_server()