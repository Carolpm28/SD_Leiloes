#Cliente de Criptografia - Integração com Servidor
import requests
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import hashlib
from server_client import ServerClient


class CryptoManager:
    #Gestor de criptografia do cliente. Comunica com servidor para obter certificados e tokens anónimos
    
    def __init__(self, server_url="http://localhost:5000", keys_dir="keys"):
        self.server_url = server_url
        self.keys_dir = keys_dir
        self.backend = default_backend()
        
        # Estado do cliente
        self.user_id = None
        self.username = None
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.ca_cert = None
        self.blind_pub_key = None  # Chave pública do servidor para blind sigs
        
        # Criar diretório para chaves
        os.makedirs(keys_dir, exist_ok=True)
        
        # Carregar certificado CA do servidor
        self._fetch_ca_certificate()
        self._fetch_blind_public_key()
        self.server_client = ServerClient()
    
    def register_with_server(self, username, ip, port):
        #Regista este cliente no servidor central
        # Obter chave pública
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Registar
        response = self.server_client.register_user(
            username=username,
            public_key=public_key_pem,
            ip=ip,
            port=port
        )
        
        if response['status'] == 'success':
            # Guardar certificado
            self.certificate = response['certificate']
            self.ca_certificate = response['ca_certificate']
            return True
        else:
            print(f"Erro no registo: {response['message']}")
            return False
    
    def get_timestamp_for_bid(self, auction_id, bid_value, token):
        #Obtém timestamp confiável do servidor
        bid_data = f"{auction_id}|{bid_value}|{token}"
        return self.server_client.request_timestamp(bid_data)
    
    def discover_peers(self):
        #Descobre outros utilizadores na rede
        return self.server_client.get_users_list()
    
    # ==================== SETUP ====================
    
    def _fetch_ca_certificate(self):
        #Obtém certificado da CA do servidor
        try:
            response = requests.get(f"{self.server_url}/api/ca/certificate")
            if response.status_code == 200:
                self.ca_cert = x509.load_pem_x509_certificate(
                    response.json()['certificate'].encode(),
                    self.backend
                )
                print("✓ CA certificate loaded")
        except Exception as e:
            print(f"Could not fetch CA certificate: {e}")
    
    def _fetch_blind_public_key(self):
        #Obtém chave pública para blind signatures
        try:
            response = requests.get(f"{self.server_url}/api/blind/public_key")
            if response.status_code == 200:
                self.blind_pub_key = serialization.load_pem_public_key(
                    response.json()['public_key'].encode(),
                    self.backend
                )
                print("Blind signature public key loaded")
        except Exception as e:
            print(f"Could not fetch blind public key: {e}")
    
    # ==================== REGISTO/LOGIN ====================
    
    def register(self, username, password, ip, port):
        #Regista utilizador no servidor
        #1. Gera par de chaves RSA
        #2. Envia chave pública ao servidor
        #3. Recebe certificado X.509 assinado pela CA
        
        try:
            # Gerar par de chaves
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            self.public_key = self.private_key.public_key()
            
            # Serializar chave pública
            pub_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            # Enviar ao servidor
            response = requests.post(f"{self.server_url}/api/register", json={
                "username": username,
                "password": password,
                "public_key": pub_key_pem,
                "ip": ip,
                "port": port
            })
            
            if response.status_code == 201:
                data = response.json()
                self.user_id = data['user_id']
                self.username = username
                self.certificate = data['certificate']
                
                # Guardar chaves localmente
                self._save_keys(username)
                
                print(f"✓ User {username} registered successfully")
                return True, "Registration successful"
            else:
                return False, response.json().get('error', 'Registration failed')
                
        except Exception as e:
            print(f"Registration error: {e}")
            return False, str(e)
    
    def login(self, username, password):
        #Faz login no servidor
        #1. Autentica com username/password
        #2. Carrega chaves locais
        #3. Recebe certificado do servidor

        try:
            # Autenticar no servidor
            response = requests.post(f"{self.server_url}/api/login", json={
                "username": username,
                "password": password
            })
            
            if response.status_code == 200:
                data = response.json()
                self.user_id = data['user_id']
                self.username = username
                self.certificate = data.get('certificate')
                
                # Carregar chaves locais
                self._load_keys(username)
                
                print(f"✓ User {username} logged in")
                return True, "Login successful"
            else:
                return False, response.json().get('error', 'Login failed')
                
        except Exception as e:
            print(f"Login error: {e}")
            return False, str(e)
    
    # ==================== BLIND SIGNATURES (ANONIMATO) ====================
    
    def request_anonymous_token(self):
        #Pede token anónimo ao servidor usando blind signatures

        if not self.blind_pub_key:
            return None, "Blind public key not available"
        
        try:
            # 1. Gerar mensagem aleatória
            import secrets
            message = f"ANON_TOKEN_{secrets.token_hex(16)}"
            
            # 2. Blind (cegar mensagem)
            blinded_msg, r, msg_hash = self._blind_message(message)
            
            # 3. Enviar ao servidor
            response = requests.post(f"{self.server_url}/api/blind/sign", json={
                "blinded_message": str(blinded_msg)
            })
            
            if response.status_code == 200:
                blinded_sig = int(response.json()['blinded_signature'])
                
                # 4. Unblind (remover cegueira)
                signature = self._unblind_signature(blinded_sig, r)
                
                # 5. Criar token
                token = self._create_token(msg_hash, signature)
                
                print("✓ Anonymous token obtained")
                return token, None
            else:
                return None, "Failed to obtain blind signature"
                
        except Exception as e:
            print(f"Token request error: {e}")
            return None, str(e)
    
    def _blind_message(self, message):
        #Cliente: cega mensagem antes de enviar
        # Hash da mensagem
        m_hash = hashlib.sha256(message.encode()).digest()
        m = int.from_bytes(m_hash, byteorder='big')
        
        # Parâmetros chave pública
        n = self.blind_pub_key.public_numbers().n
        e = self.blind_pub_key.public_numbers().e
        
        # Gerar blinding factor
        import secrets
        r = secrets.randbelow(n - 1) + 1
        r_e = pow(r, e, n)
        
        # m' = m * r^e mod n
        m_blinded = (m * r_e) % n
        
        return m_blinded, r, m_hash
    
    def _unblind_signature(self, blinded_sig, r):
        #Cliente: remove cegueira da assinatura
        n = self.blind_pub_key.public_numbers().n
        r_inv = pow(r, -1, n)
        signature = (blinded_sig * r_inv) % n
        return signature
    
    def _create_token(self, msg_hash, signature):
        #Cria token no formato esperado pelo servidor
        sig_bytes = signature.to_bytes(256, byteorder='big')  # 2048 bits = 256 bytes
        token = msg_hash.hex() + ":" + sig_bytes.hex()
        return token
    
    # ==================== ASSINATURAS NORMAIS ====================
    
    def sign_data(self, data):
        #Assina dados com chave privada (RSA-PSS). Usa para leilões/bids quando NÃO quer anonimato para o servidor, quando o servidor tem que verificar a nossa identidade.
 
        if not self.private_key:
            raise Exception("No private key loaded")
        
        # Serializar data para bytes
        if isinstance(data, dict):
            data_bytes = json.dumps(data, sort_keys=True).encode()
        elif isinstance(data, str):
            data_bytes = data.encode()
        else:
            data_bytes = data
        
        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature.hex()
    
    def verify_signature(self, data, signature_hex, public_key_pem):
        #Verifica assinatura RSA-PSS
        try:
            # Carregar chave pública
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                self.backend
            )
            
            # Preparar dados
            if isinstance(data, dict):
                data_bytes = json.dumps(data, sort_keys=True).encode()
            elif isinstance(data, str):
                data_bytes = data.encode()
            else:
                data_bytes = data
            
            signature = bytes.fromhex(signature_hex)
            
            # Verificar
            public_key.verify(
                signature,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    # ==================== GESTÃO DE CHAVES ====================
    
    def _save_keys(self, username):
        #Guarda chaves no disco
        # Chave privada
        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # TODO: Adicionar password
        )
        
        with open(f"{self.keys_dir}/{username}_private.pem", "wb") as f:
            f.write(priv_pem)
        
        # Chave pública
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(f"{self.keys_dir}/{username}_public.pem", "wb") as f:
            f.write(pub_pem)
        
        # Certificado (se existir)
        if self.certificate:
            with open(f"{self.keys_dir}/{username}_cert.pem", "w") as f:
                f.write(self.certificate)
    
    def _load_keys(self, username):
        #Carrega chaves do disco
        try:
            # Chave privada
            with open(f"{self.keys_dir}/{username}_private.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=self.backend
                )
            
            # Chave pública
            with open(f"{self.keys_dir}/{username}_public.pem", "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    self.backend
                )
            
            # Certificado (se existir)
            cert_path = f"{self.keys_dir}/{username}_cert.pem"
            if os.path.exists(cert_path):
                with open(cert_path, "r") as f:
                    self.certificate = f.read()
            
            print(f"Keys loaded for {username}")
            
        except FileNotFoundError:
            print(f"No keys found for {username}")
    
    def get_anonymous_id(self):
        #Retorna ID anónimo (hash da chave pública). Usado para identificar-se sem revelar identidade

        if not self.public_key:
            return None
        
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return hashlib.sha256(pub_pem).hexdigest()[:16]


# ==================== TESTES ====================

if __name__ == "__main__":
    print("=== CryptoManager Test ===\n")
    
    cm = CryptoManager(server_url="http://localhost:5000")
    
    # Simular registo
    # success, msg = cm.register("alice", "password123", "192.168.1.10", 5001)
    # print(f"Register: {success} - {msg}\n")
    
    # Simular obtenção de token anónimo
    # token, error = cm.request_anonymous_token()
    # if token:
    #     print(f"Token: {token[:60]}...\n")