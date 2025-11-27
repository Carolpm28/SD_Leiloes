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
    
    def __init__(self, keys_dir="keys"):
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
        self._ca_cert_loaded = False
        self._blind_key_loaded = False
        self.server_client = ServerClient()

    # ==================== LAZY LOADING ====================
    
    def _ensure_ca_certificate(self):
        #Carrega certificado CA apenas quando necessário
        if not self._ca_cert_loaded:
            self._fetch_ca_certificate()
            self._ca_cert_loaded = True
    
    def _ensure_blind_public_key(self):
        #Carrega chave pública blind apenas quando necessário
        if not self._blind_key_loaded:
            self._fetch_blind_public_key()
            self._blind_key_loaded = True

    def get_ca_certificate(self):
        #Retorna certificado CA (lazy loading)
        self._ensure_ca_certificate()
        return self.ca_cert
    
    def get_blind_public_key(self):
        #Retorna chave pública blind (lazy loading)
        self._ensure_blind_public_key()
        return self.blind_pub_key
    

    
    def get_timestamp_for_bid(self, auction_id, bid_value, token):
        #Obtém timestamp confiável do servidor
        bid_data = f"{auction_id}|{bid_value}|{token}"
        return self.server_client.request_timestamp(bid_data)
    
    def discover_peers(self):
        #Descobre outros utilizadores na rede
        return self.server_client.get_users_list()
    
    # ==================== SETUP ====================
    
    def _fetch_ca_certificate(self):
        #Obtém certificado da CA do servidor via ServerClient"""
        try:
            ca_cert_pem = self.server_client.get_ca_certificate()
            if ca_cert_pem:
                self.ca_cert = x509.load_pem_x509_certificate(
                    ca_cert_pem.encode(),
                    self.backend
                )
                print("CA certificate loaded")
        except Exception as e:
            print(f"Could not fetch CA certificate: {e}")
    
    def _fetch_blind_public_key(self):
        #Obtém chave pública para blind signatures via ServerClient
        try:
            # Pedir token só para obter a chave pública
            response = self.server_client.get_blind_token("dummy_message")
            if response and 'blind_public_key' in response:
                self.blind_pub_key = serialization.load_pem_public_key(
                    response['blind_public_key'].encode(),
                    self.backend
                )
                print("Blind signature public key loaded")
        except Exception as e:
            print(f"Could not fetch blind public key: {e}")
    
    # ==================== REGISTO/LOGIN ====================
    
    def register(self, username, password, ip, port):
        """Regista utilizador no servidor
        1. Gera par de chaves RSA
        2. Envia chave pública ao servidor
        3. Recebe certificado X.509 assinado pela CA
        """
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
            
            response = self.server_client.register_user(
                username=username,
                public_key=pub_key_pem,
                ip=ip,
                port=port
            )
            
            if response.get('status') == 'success':
                self.user_id = response['user_id']
                self.username = username
                self.certificate = response['certificate']
                
                # Guardar chaves localmente
                self._save_keys(username)
                
                print(f"User {username} registered successfully")
                return True, "Registration successful"
            else:
                error_msg = response.get('message', 'Registration failed')
                return False, error_msg
                
        except Exception as e:
            print(f"Registration error: {e}")
            return False, str(e)
    def login(self, username, password):
        #faz login no servidor
        try:
            response = self.server_client.login_user(username, password)
            
            print(f"[DEBUG] Server response: {response}")
            
            if response.get('status') == 'success':
                self.user_id = response['user_id']
                self.username = username
                self.certificate = response.get('certificate')
                
                # Carregar chaves locais
                self._load_keys(username)
                
                print(f"User {username} logged in")
                return True, "Login successful"
            else:
                error_msg = response.get('message', 'Login failed')
                return False, error_msg
                
        except Exception as e:
            print(f"Login error: {e}")
            return False, str(e)
    
    # ==================== BLIND SIGNATURES (ANONIMATO) ====================
    
    def request_anonymous_token(self):
        #Pede token anónimo ao servidor usando blind signatures
        self._ensure_blind_public_key()
        
        if not self.blind_pub_key:
            return None, "Blind public key not available"
        
        try:
            import secrets
            message = f"ANON_TOKEN_{secrets.token_hex(16)}"
            
            # Blind (cegar mensagem)
            blinded_msg, r, msg_hash = self._blind_message(message)
            
            response = self.server_client.get_blind_token(str(blinded_msg))
            
            if response and response.get('status') == 'success':
                blinded_sig = int(response['blind_signature'], 16)  # hex to int
                
                # Unblind
                signature = self._unblind_signature(blinded_sig, r)
                
                # Criar token
                token = self._create_token(msg_hash, signature)
                
                print("Anonymous token obtained")
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
    
    