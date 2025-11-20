"""
Servidor Central do Sistema de Leilões P2P
Todas as chaves guardadas na BD
"""
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

import asyncio
import json
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from crypto.cert_auth import AuctionCA
from crypto.blind_signature import BlindSignature

# ============================================================================
# CONFIGURAÇÃO GLOBAL
# ============================================================================

DB_PATH = 'server.db'
SERVER_CERT_PEM = None          # Certificado da CA (público)
SERVER_PRIV_KEY = None          # Chave privada da CA (secreta)
SERVER_BLIND_PRIV_KEY = None    # Chave privada para blind signatures
SERVER_BLIND_PUB_KEY = None     # Chave pública para blind signatures
CA = None                        # Objeto AuctionCA
BLIND_SIG = None                 # Objeto BlindSignature

# Configuração da rede
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999

# ============================================================================
# INICIALIZAÇÃO
# ============================================================================

def init_db():
    """Inicializa a base de dados"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Tabela de utilizadores
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL
        )
    ''')
    
    # Tabela tokens anónimos
    c.execute('''
        CREATE TABLE IF NOT EXISTS anonymous_tokens (
            token_hash TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP
        )
    ''')
    
    # Tabela certificados da CA
    c.execute('''
        CREATE TABLE IF NOT EXISTS ca_certs (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            ca_cert_pem BLOB,
            ca_priv_key_pem BLOB
        )
    ''')
    
    # Tabela chave blind
    c.execute('''
        CREATE TABLE IF NOT EXISTS blind_signature_keys (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            blind_priv_key_pem BLOB,
            blind_pub_key_pem BLOB
        )
    ''')
    
    # Tabela de timestamps
    c.execute('''
        CREATE TABLE IF NOT EXISTS timestamps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bid_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()


def init_auction_ca():
    """Inicializa a Certificate Authority"""
    global SERVER_CERT_PEM, SERVER_PRIV_KEY, CA
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ca_cert_pem, ca_priv_key_pem FROM ca_certs WHERE id=1')
    row = c.fetchone()
    
    if row and row[0] and row[1]:
        ca_cert_pem, ca_key_pem = row
        SERVER_CERT_PEM = ca_cert_pem
        SERVER_PRIV_KEY = serialization.load_pem_private_key(
            ca_key_pem,
            password=None,
            backend=default_backend()
        )
        ca = AuctionCA(ca_key_pem=ca_key_pem, ca_cert_pem=ca_cert_pem)
    else:
        ca = AuctionCA()
        ca_cert_pem = ca.ca_cert.public_bytes(serialization.Encoding.PEM)
        SERVER_CERT_PEM = ca_cert_pem
        
        priv_key_pem = ca.ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        SERVER_PRIV_KEY = ca.ca_private_key
        
        c.execute('INSERT OR REPLACE INTO ca_certs (id, ca_cert_pem, ca_priv_key_pem) VALUES (1, ?, ?)',
                  (ca_cert_pem, priv_key_pem))
        conn.commit()
    
    conn.close()
    CA = ca
    return ca


def init_blind_signature_keys():
    """Inicializa as chaves para blind signatures"""
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
        print("  ↪ Generating new blind signature keys...")
        
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
        print("  ✓ Blind signature keys generated and stored")
    
    conn.close()
    
    BLIND_SIG = BlindSignature()
    print("  ✓ Blind signature handler ready")


# ============================================================================
# HANDLERS DAS MENSAGENS
# ============================================================================

async def handle_register(data):
    """Regista novo utilizador e emite certificado"""
    conn = None
    try:
        username = data['username']
        pub_key_pem = data['public_key']
        ip = data['ip']
        port = data['port']
        
        # Gerar user_id
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pub_key_pem.encode())
        user_id = digest.finalize().hex()[:16]
        
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO users (user_id, username, public_key, ip, port)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, username, pub_key_pem, ip, port))
        conn.commit()
        
        # Converter PEM para objeto
        from cryptography.hazmat.primitives import serialization
        user_public_key = serialization.load_pem_public_key(
            pub_key_pem.encode(),
            backend=default_backend()
        )
        
        # Emitir certificado
        cert_pem = CA.issue_certificate(user_id, username, user_public_key)
        
        # ← VERIFICAR TIPO
        if isinstance(cert_pem, bytes):
            cert_str = cert_pem.decode()
        else:
            cert_str = cert_pem
        
        if isinstance(SERVER_CERT_PEM, bytes):
            ca_cert_str = SERVER_CERT_PEM.decode()
        else:
            ca_cert_str = SERVER_CERT_PEM
        
        return {
            'status': 'success',
            'user_id': user_id,
            'certificate': cert_str,
            'ca_certificate': ca_cert_str
        }
    
    except sqlite3.IntegrityError:
        return {'status': 'error', 'message': 'Username already exists'}
    except Exception as e:
        print(f"  Register error: {e}")
        import traceback
        traceback.print_exc()
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()


async def handle_login(data):
    #Autentica utilizador existente
    conn = None
    try:
        username = data['username']
        password = data['password']  # TODO: verificar password hash
        
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        
        # procurar utilizador
        c.execute('''
            SELECT user_id, public_key FROM users WHERE username = ?
        ''', (username,))
        
        row = c.fetchone()
        
        if not row:
            return {'status': 'error', 'message': 'User not found'}
        
        user_id, pub_key_pem = row
        
        # Converter PEM para objeto de chave pública
        from cryptography.hazmat.primitives import serialization
        user_public_key = serialization.load_pem_public_key(
            pub_key_pem.encode(),
            backend=default_backend()
        )
        
        # Emitir novo certificado
        cert_pem = CA.issue_certificate(user_id, username, user_public_key)
        
        # ← VERIFICAR SE É STRING OU BYTES
        if isinstance(cert_pem, bytes):
            cert_str = cert_pem.decode()
        else:
            cert_str = cert_pem
        
        if isinstance(SERVER_CERT_PEM, bytes):
            ca_cert_str = SERVER_CERT_PEM.decode()
        else:
            ca_cert_str = SERVER_CERT_PEM
        
        return {
            'status': 'success',
            'user_id': user_id,
            'certificate': cert_str,
            'ca_certificate': ca_cert_str
        }
    
    except Exception as e:
        print(f"  Login error: {e}")
        import traceback
        traceback.print_exc()  # ← DEBUG detalhado
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()

async def handle_get_blind_token(data):
    """Emite token cego para anonimato"""
    conn = None
    try:
        blinded_msg = data['blinded_message']
        
        # Assinar diretamente com a chave privada
        signature = SERVER_BLIND_PRIV_KEY.sign(
            blinded_msg.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Guardar hash do token
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(blinded_msg.encode())
        token_hash = digest.finalize().hex()
        
        # Guardar na BD com retry
        max_retries = 3
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(DB_PATH, timeout=10.0)
                c = conn.cursor()
                c.execute('INSERT INTO anonymous_tokens (token_hash, used) VALUES (?, 0)', 
                         (token_hash,))
                conn.commit()
                break
            except sqlite3.OperationalError:
                if attempt == max_retries - 1:
                    raise
                import time
                time.sleep(0.1)
        
        return {
            'status': 'success',
            'blind_signature': signature.hex(),
            'blind_public_key': SERVER_BLIND_PUB_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
    
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()


async def handle_verify_token(data):
    """Verifica se um token anónimo é válido"""
    conn = None
    try:
        token_hash = data['token_hash']
        
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        c.execute('SELECT used FROM anonymous_tokens WHERE token_hash = ?', (token_hash,))
        row = c.fetchone()
        
        if not row:
            return {'status': 'error', 'message': 'Token not found'}
        
        if row[0] == 1:
            return {'status': 'error', 'message': 'Token already used'}
        
        # Marcar como usado
        c.execute('''
            UPDATE anonymous_tokens 
            SET used = 1, used_at = ? 
            WHERE token_hash = ?
        ''', (datetime.now().isoformat(), token_hash))
        conn.commit()
        
        return {'status': 'success', 'message': 'Token valid'}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()


async def handle_get_users(data):
    """Lista utilizadores registados (descoberta P2P)"""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        c.execute('SELECT user_id, username, ip, port FROM users')
        rows = c.fetchall()
        
        users = [
            {'user_id': r[0], 'username': r[1], 'ip': r[2], 'port': r[3]}
            for r in rows
        ]
        
        return {'status': 'success', 'users': users}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()


async def handle_timestamp(data):
    """Gera timestamp confiável para lance"""
    conn = None
    try:
        bid_data = data['bid_data']
        
        # Criar timestamp
        timestamp = datetime.now().isoformat()
        message = f"{bid_data}|{timestamp}"
        
        # Assinar
        signature = SERVER_PRIV_KEY.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Guardar na BD
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bid_data.encode())
        bid_hash = digest.finalize().hex()
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(DB_PATH, timeout=10.0)
                c = conn.cursor()
                c.execute('''
                    INSERT INTO timestamps (bid_hash, timestamp, signature)
                    VALUES (?, ?, ?)
                ''', (bid_hash, timestamp, signature.hex()))
                conn.commit()
                break
            except sqlite3.OperationalError:
                if attempt == max_retries - 1:
                    raise
                import time
                time.sleep(0.1)
        
        return {
            'status': 'success',
            'timestamp': timestamp,
            'signature': signature.hex(),
            'ca_certificate': SERVER_CERT_PEM.decode()
        }
    
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()


async def handle_get_ca_cert(data):
    """Retorna certificado da CA"""
    return {
        'status': 'success',
        'ca_certificate': SERVER_CERT_PEM.decode()
    }


# ============================================================================
# ROUTING TABLE
# ============================================================================

HANDLERS = {
    'register': handle_register,
    'get_blind_token': handle_get_blind_token,
    'verify_token': handle_verify_token,
    'get_users': handle_get_users,
    'timestamp': handle_timestamp,
    'get_ca_cert': handle_get_ca_cert,
}


# ============================================================================
# SERVIDOR ASSÍNCRONO
# ============================================================================

async def handle_client(reader, writer):
    """Handle client connection"""
    addr = writer.get_extra_info('peername')
    print(f"→ Connection from {addr}")
    
    try:
        data_bytes = await reader.read(100000)
        data = json.loads(data_bytes.decode())
        
        action = data.get('action')
        print(f"  Action: {action}")
        
        # Route to appropriate handler
        if action == 'register':
            response = await handle_register(data)
        elif action == 'login':
            response = await handle_login(data)
        elif action == 'get_users':
            response = await handle_get_users()
        elif action == 'get_ca_cert':
            response = await handle_get_ca_cert(data)  
        elif action == 'get_blind_token':
            response = await handle_get_blind_token(data)
        elif action == 'timestamp':
            response = await handle_timestamp(data)
        else:
            response = {'status': 'error', 'message': f'Unknown action: {action}'}
        
        # Send response
        response_bytes = json.dumps(response).encode()
        writer.write(response_bytes)
        await writer.drain()
        print(f"Response sent\n")
        
    except Exception as e:
        print(f"Error: {e}\n")
        error_response = {'status': 'error', 'message': str(e)}
        writer.write(json.dumps(error_response).encode())
        await writer.drain()
    
    finally:
        writer.close()
        await writer.wait_closed()


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
    print(f"✓ Server listening on {SERVER_HOST}:{SERVER_PORT}")
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
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_server()