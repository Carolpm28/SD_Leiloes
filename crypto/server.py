#Servidor Central do Sistema de Leilões P2P
#Todas as chaves guardadas na BD
import ssl
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import bcrypt
import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from crypto.cert_auth import AuctionCA
from crypto.blind_signature import BlindSignature
from crypto.challenge_manager import Challenge_Manager

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
TIMESTAMP_SERVICE = None       # Serviço de timestamping
CHALLENGE_MANAGER = Challenge_Manager(expiration_time=60)  # Iniciar gestor globalmente

# Configuração da rede
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999

# ============================================================================
# INICIALIZAÇÃO
# ============================================================================

def init_db():
    #Inicializa a base de dados
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # TABELA PARA SSL
    c.execute('''
        CREATE TABLE IF NOT EXISTS ssl_keys (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cert_pem BLOB,
            key_pem BLOB
        )
    ''')

    # Tabela de utilizadores
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
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

def init_ssl_keys():
    """
    Gere chaves SSL:
    1. Tenta carregar da BD.
    2. Se não existir, gera novas e guarda na BD.
    3. Escreve ficheiros físicos (.pem) para o módulo SSL usar.
    """
    print("[SSL] Checking SSL keys...")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT cert_pem, key_pem FROM ssl_keys WHERE id=1')
    row = c.fetchone()
    
    cert_pem = None
    key_pem = None

    if row and row[0] and row[1]:
        print("  ✓ Found SSL keys in database")
        cert_pem = row[0]
        key_pem = row[1]
    else:
        print("  ↪ Generating new Self-Signed SSL Certificate...")
        
        # 1. Gerar Chave Privada
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 2. Gerar Certificado Auto-assinado
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"P2P Auction Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        # 3. Converter para PEM (bytes)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        # 4. Guardar na BD
        c.execute('INSERT OR REPLACE INTO ssl_keys (id, cert_pem, key_pem) VALUES (1, ?, ?)', 
                  (cert_pem, key_pem))
        conn.commit()
        print("  ✓ New SSL keys generated and saved to DB")

    conn.close()

    # 5. Escrever para ficheiros físicos (Obrigatório para o ssl.create_default_context)
    # Sempre que o servidor arranca, garante que os ficheiros no disco batem certo com a BD
    with open("server_cert.pem", "wb") as f:
        f.write(cert_pem)
        
    with open("server_key.pem", "wb") as f:
        f.write(key_pem)
        
    print("  ✓ SSL files 'server_cert.pem' and 'server_key.pem' exported/verified")


def init_auction_ca():
    #Inicializa a Certificate Authority
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

def init_timestamp_service():
    #Inicializa o serviço de timestamping
    global TIMESTAMP_SERVICE
    
    from crypto.timestamp_service import TimestampService
    TIMESTAMP_SERVICE = TimestampService(db_path=DB_PATH)
    print("Timestamp service initialized")

def init_blind_signature_keys():
    #Inicializa as chaves para blind signatures
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
        print("Blind signature keys loaded from database")
    else:
        print("Generating new blind signature keys...")
        
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
        print("Blind signature keys generated and stored")
    
    conn.close()
    
    BLIND_SIG = BlindSignature()
    print("Blind signature handler ready")


# ============================================================================
# HANDLERS DAS MENSAGENS
# ============================================================================

async def handle_get_challenge(data):

    """
    Gera desafio genérico para autenticação do utilizador
    """
    print("[CHALLENGE] Generating challenge...")
    conn = None
    try:
        username = data['username']

        #fetch da chave pub do user
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT public_key FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        if not row:
            return {'status': 'error', 'message': 'User not found'}
        pub_key_pem = row[0]

        print(f"[CHALLENGE] Generating challenge for user: {username}")

        #usar o challenge manager
        encrypted_challenge = CHALLENGE_MANAGER.generate_challenge(username, pub_key_pem)

        print(f"[DEBUG] Generated challenge len: {len(encrypted_challenge) if encrypted_challenge else 'None'}")
        if encrypted_challenge:
            return {
                'status': 'success',
                'encrypted_challenge': encrypted_challenge
            }
        else:
            return {'status': 'error', 'message': 'Failed to generate challenge'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()

async def handle_register(data):
    #Regista novo utilizador e emite certificado
    conn = None
    try:
        username = data['username']
        password = data['password']
        pub_key_pem = data['public_key']
        ip = data['ip']
        port = data['port']
        
        #Hash da password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Gerar user_id
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pub_key_pem.encode())
        user_id = digest.finalize().hex()[:16]
        
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        
        #Inserir com password_hash
        c.execute('''
            INSERT INTO users (user_id, username, password_hash, public_key, ip, port)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, password_hash.decode('utf-8'), pub_key_pem, ip, port))
        conn.commit()
        
        # Converter PEM para objeto
        from cryptography.hazmat.primitives import serialization
        user_public_key = serialization.load_pem_public_key(
            pub_key_pem.encode(),
            backend=default_backend()
        )
        
        # Emitir certificado
        cert_pem = CA.issue_certificate(user_id, username, user_public_key)
        
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
        password = data['password']
        nonce_solution = data['nonce_solution']

        if not nonce_solution:
            return {'status': 'error', 'message': 'No nonce solution provided'}
        
        #Verificar nonce
        if not CHALLENGE_MANAGER.verify_response(username, nonce_solution):
            return {'status': 'error', 'message': 'Invalid or expired challenge response'}

        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        
        #Procura o user_id, password_hash e public_key
        c.execute('''
            SELECT user_id, password_hash, public_key FROM users WHERE username = ?
        ''', (username,))
        
        row = c.fetchone()
        
        if not row:
            return {'status': 'error', 'message': 'User not found'}
        
        user_id, password_hash, pub_key_pem = row
        
        #Verificar password
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            return {'status': 'error', 'message': 'Invalid password'}
        
        # Converter PEM para objeto de chave pública
        from cryptography.hazmat.primitives import serialization
        user_public_key = serialization.load_pem_public_key(
            pub_key_pem.encode(),
            backend=default_backend()
        )
        
        # Emitir novo certificado
        cert_pem = CA.issue_certificate(user_id, username, user_public_key)
        
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
        traceback.print_exc()
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()

async def handle_get_blind_token(data):
    #Emite token cego para anonimato
    conn = None
    try:
        # 1. Receber mensagem cega como STRING (JSON não suporta int grande)
        blinded_msg_str = data['blinded_message']
        
        # 2. Converter STRING -> INT
        blinded_msg = int(blinded_msg_str)
        
        # 3. Usar a classe BlindSignature correta
        blinded_sig = BLIND_SIG.blind_sign(blinded_msg, SERVER_BLIND_PRIV_KEY)
        
        # 4. Guardar hash do token (para tracking)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(blinded_msg_str.encode())
        token_hash = digest.finalize().hex()
        
        # 5. Guardar na BD
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
        
        # 6. Retornar como STRING (para JSON)
        return {
            'status': 'success',
            'blind_signature': str(blinded_sig),  # INT -> STRING
            'blind_public_key': SERVER_BLIND_PUB_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
    
    except Exception as e:
        print(f"Blind token error: {e}")
        import traceback
        traceback.print_exc()
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()


async def handle_verify_token(data):
    #Verifica se um token anónimo é válido
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


async def handle_get_users(data=None):
    #Retorna lista de utilizadores registados
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        
        c.execute('''
            SELECT user_id, username, ip, port FROM users
        ''')
        
        users = []
        for row in c.fetchall():
            users.append({
                'user_id': row[0],
                'username': row[1],
                'ip': row[2],
                'port': row[3]
            })
        
        return {
            'status': 'success',
            'users': users
        }
    
    except Exception as e:
        print(f"  Get users error: {e}")
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()


async def handle_timestamp(data):
    #Gera timestamp confiável para lance
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
    #Retorna certificado da CA
    return {
        'status': 'success',
        'ca_certificate': SERVER_CERT_PEM.decode()
    }

async def handle_update_address(data):
   #Atualiza IP e porta de um utilizador
    conn = None
    try:
        user_id = data['user_id']
        ip = data['ip']
        port = data['port']
        
        conn = sqlite3.connect(DB_PATH, timeout=10.0)
        c = conn.cursor()
        
        c.execute('''
            UPDATE users SET ip = ?, port = ? WHERE user_id = ?
        ''', (ip, port, user_id))
        conn.commit()
        
        print(f"  Updated address for {user_id}: {ip}:{port}")
        
        return {'status': 'success'}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
    finally:
        if conn:
            conn.close()



async def handle_get_blind_key(data):
    # Retorna a chave pública usada para Blind Signatures
    return {
        'status': 'success',
        'blind_public_key': SERVER_BLIND_PUB_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
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
    'get_blind_key': handle_get_blind_key,
    'get_challenge': handle_get_challenge,
    'login': handle_login,
}


# ============================================================================
# SERVIDOR ASSÍNCRONO
# ============================================================================


async def handle_client(reader, writer):
    #Handle client connection
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
            response = await handle_get_users(data)
        elif action == 'get_ca_cert':
            response = await handle_get_ca_cert(data)  
        elif action == 'get_blind_token':
            response = await handle_get_blind_token(data)
        elif action == 'timestamp':
            response = await handle_timestamp(data)
        elif action == 'update_address':
            response = await handle_update_address(data)
        elif action == 'get_blind_key':
            response = await handle_get_blind_key(data)
        elif action == "get_challenge":
            response = await handle_get_challenge(data)
        elif action == "login":
            response = await handle_login(data)
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
    #Função principal do servidor
    print("=" * 60)
    print("SERVIDOR DE LEILÕES P2P")
    print("=" * 60)
    
    # Inicializar componentes
    print("\n[1/5] Initializing database...")
    init_db()
    
    print("[2/5] Initializing Certificate Authority...")
    init_auction_ca()
    
    print("[3/5] Initializing Blind Signature system...")
    init_blind_signature_keys()
    
    print("[4/5] Initializing Time-stamping service...")
    init_timestamp_service()

    print("[5/5] Initializing SSL keys...")
    init_ssl_keys()
    
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    try:
        ssl_context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")
    except Exception as e:
        print(f"Failed to load SSL certificates: {e}")
        return

    print("\n" + "=" * 60)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}" " (SSL/TLS enabled)")
    print("=" * 60 + "\n")

    # Criar servidor TCP
    server = await asyncio.start_server(
        handle_client,
        SERVER_HOST,
        SERVER_PORT,
        ssl=ssl_context
    )
    
    # Manter servidor a correr
    async with server:
        await server.serve_forever()


def run_server():
    #Entry point do servidor
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nServer shutdown requested")
    except Exception as e:
        print(f"\nServer error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_server()