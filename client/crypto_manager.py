# Cliente de Criptografia - Integração com Servidor
import requests
import json
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from server_client import ServerClient

class CryptoManager:
    # Gestor de criptografia do cliente
    
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
        self.blind_pub_key = None
        self._notary_key_loaded = False
        self.notary_pub_key = None
        
        # Criar diretório para chaves
        os.makedirs(keys_dir, exist_ok=True)
        
        # Carregar certificado CA do servidor
        self._ca_cert_loaded = False
        self._blind_key_loaded = False
        self.server_client = ServerClient()
        

    # === FUNÇÕES PARA REVELAÇÃO DE IDENTIDADE ===

    def _fetch_notary_public_key(self):
        # Vai buscar a chave pública do Notário ao servidor
        try:
            response = self.server_client.request('GET_NOTARY_PUB_KEY', {}) # Assumindo um novo endpoint no server.py
            
            if response and response.get('status') == 'success':
                pub_key_pem = response.get('notary_pub_key')
                self.notary_pub_key = serialization.load_pem_public_key(
                    pub_key_pem.encode(),
                    backend=self.backend
                )
                print("Notary Public Key obtained.")
                return True
            else:
                print(f"Failed to fetch Notary Public Key: {response}")
                return False
        except Exception as e:
            print(f"Error fetching Notary Public Key: {e}")
            return False

    def _ensure_notary_key(self):
        # Carrega a chave do Notário apenas quando necessário
        if not self._notary_key_loaded:
            self._fetch_notary_public_key()
            self._notary_key_loaded = True

    def generate_ephemeral_keys(self):
        """
        Gera um par de chaves RSA temporário para um leilão específico.
        Retorna: (private_key_pem, public_key_pem)
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            priv_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            pub_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            return priv_pem, pub_pem
        except Exception as e:
            print(f"Erro ao gerar chaves efémeras: {e}")
            return None, None
    
    def encrypt_identity_for_notary(self, auction_id: str, bid_value: float) -> str:
        # Cifra a identidade real (Certificado) usando a Chave Pública do Notário
        self._ensure_notary_key()
        
        if not self.notary_pub_key or not self.certificate:
            raise Exception("Cannot encrypt identity: Notary key or user certificate missing.")
            
        # 1. Cria o pacote JSON (com assinatura real para não-repúdio)
        identity_data = {
            "user_id": self.user_id,
            "username": self.username,
            "auction_id": auction_id,
            "bid_value": bid_value,
            # (A Assinatura real do Bid já foi feita e verificada pelo servidor, aqui incluímos o username/ID)
        }
        
        data_bytes = json.dumps(identity_data).encode('utf-8')
        
        # 2. Cifra o pacote com a chave pública do Notário
        encrypted_bytes = self.notary_pub_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Retorna o blob cifrado em formato hex
        return encrypted_bytes.hex()
    
    def get_certificate(self):
        """Retorna o certificado para enviar ao vendedor"""
        return self.certificate

    def extract_name_from_cert(self, cert_pem):
        """Extrai o Common Name (CN) de uma string de certificado PEM"""
        try:
            if isinstance(cert_pem, str):
                cert_pem = cert_pem.encode()
                
            cert = x509.load_pem_x509_certificate(cert_pem, self.backend)
            attributes = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            
            if attributes:
                return attributes[0].value
            return "Unknown User"
        except Exception as e:
            print(f"Erro a ler certificado: {e}")
            return "Invalid Cert"

    # ==================== LAZY LOADING ====================
    
    def _ensure_ca_certificate(self):
        if not self._ca_cert_loaded:
            self._fetch_ca_certificate()
            self._ca_cert_loaded = True
    
    def _ensure_blind_public_key(self):
        if not self._blind_key_loaded:
            self._fetch_blind_public_key()
            self._blind_key_loaded = True

    def get_ca_certificate(self):
        self._ensure_ca_certificate()
        return self.ca_cert
    
    def get_blind_public_key(self):
        self._ensure_blind_public_key()
        return self.blind_pub_key
    
    def get_timestamp_for_bid(self, auction_id, bid_value, token):
        bid_data = f"{auction_id}|{bid_value}|{token}"
        return self.server_client.request_timestamp(bid_data)
    
    def discover_peers(self):
        return self.server_client.get_users_list()
    
    # ==================== SETUP ====================
    
    def _fetch_ca_certificate(self):
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
        try:
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
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            self.public_key = self.private_key.public_key()
            
            pub_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            payload_to_sign = f"{username}|{pub_key_pem}".encode('utf-8')

            signature = self.private_key.sign(
                payload_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            ).hex()

            response = self.server_client.register_user(
                username=username,
                public_key=pub_key_pem,
                ip=ip,
                port=port,
                password=password,
                signature=signature
            )
            
            if response.get('status') == 'success':
                self.user_id = response['user_id']
                self.username = username
                self.certificate = response['certificate']
                self._save_keys(username)
                print(f"User {username} registered successfully")
                return True, "Registration successful"
            else:
                return False, response.get('message', 'Registration failed')
                
        except Exception as e:
            print(f"Registration error: {e}")
            return False, str(e)
        
    def login(self, username, password):
        try:
            if not self._load_keys(username):
                return False, "User keys not found. Please register first."
            
            nonce_solution = self.solve_challenge(username)
            if not nonce_solution:
                return False, "Failed to solve challenge from server."

            response = self.server_client.login_user(username, password, nonce_solution)
            
            if response.get('status') == 'success':
                self.user_id = response['user_id']
                self.username = username
                self.certificate = response.get('certificate')
                self._load_keys(username)
                print(f"User {username} logged in")
                return True, "Login successful"
            else:
                return False, response.get('message', 'Login failed')
                
        except Exception as e:
            print(f"Login error: {e}")
            return False, str(e)
    
    def decrypt_challenge(self, encrypted_hex):
        try:
            encryted_bytes = bytes.fromhex(encrypted_hex)
            decrypted_nonce = self.private_key.decrypt(
                encryted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_nonce.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
        
    def solve_challenge(self,username):
        try:
            print(f"[DEBUG] Requesting challenge from server...")
            response = self.server_client.get_login_challenge(username)
            if response.get('status') != 'success':
                print(f"Challenge error: {response.get('message')}")
                return None
            
            encrypted_challenge = response.get('encrypted_challenge')
            return self.decrypt_challenge(encrypted_challenge)
        except Exception as e:
            print(f"Solve challenge error: {e}")
            return None

    # ==================== BLIND SIGNATURES ====================
    
    def request_anonymous_token(self):
        self._ensure_blind_public_key()
        if not self.blind_pub_key:
            return None, "Blind public key not available"
        
        try:
            import secrets
            message = f"ANON_TOKEN_{secrets.token_hex(16)}"
            blinded_msg, r, msg_hash = self._blind_message(message)
            response = self.server_client.get_blind_token(str(blinded_msg))
            
            if response and response.get('status') == 'success':
                blinded_sig = int(response['blind_signature'], 16)
                signature = self._unblind_signature(blinded_sig, r)
                token = self._create_token(msg_hash, signature)
                return token, None
            else:
                return None, "Failed to obtain blind signature"
        except Exception as e:
            return None, str(e)
    
    def _blind_message(self, message):
        m_hash = hashlib.sha256(message.encode()).digest()
        m = int.from_bytes(m_hash, byteorder='big')
        n = self.blind_pub_key.public_numbers().n
        e = self.blind_pub_key.public_numbers().e
        
        import secrets
        r = secrets.randbelow(n - 1) + 1
        r_e = pow(r, e, n)
        m_blinded = (m * r_e) % n
        
        return m_blinded, r, m_hash
    
    def _unblind_signature(self, blinded_sig, r):
        n = self.blind_pub_key.public_numbers().n
        r_inv = pow(r, -1, n)
        signature = (blinded_sig * r_inv) % n
        return signature
    
    def _create_token(self, msg_hash, signature):
        sig_bytes = signature.to_bytes(256, byteorder='big')
        token = msg_hash.hex() + ":" + sig_bytes.hex()
        return token
    
    # ==================== ASSINATURAS NORMAIS ====================
    
    def sign_data(self, data):
        if not self.private_key:
            raise Exception("No private key loaded")
        
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
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                self.backend
            )
            if isinstance(data, dict):
                data_bytes = json.dumps(data, sort_keys=True).encode()
            elif isinstance(data, str):
                data_bytes = data.encode()
            else:
                data_bytes = data
            
            signature = bytes.fromhex(signature_hex)
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
        try:
            abs_keys_dir = os.path.abspath(self.keys_dir)
            os.makedirs(abs_keys_dir, exist_ok=True)

            priv_path = os.path.join(abs_keys_dir, f"{username}_private.pem")
            priv_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(priv_path, "wb") as f:
                f.write(priv_pem)
            
            pub_path = os.path.join(abs_keys_dir, f"{username}_public.pem")
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
            
            if self.certificate:
                cert_path = os.path.join(abs_keys_dir, f"{username}_cert.pem")
                with open(cert_path, "w") as f:
                    f.write(self.certificate)
        except Exception as e:
            print(f"Erro ao guardar chaves: {e}")
    
    def _load_keys(self, username):
        try:
            with open(f"{self.keys_dir}/{username}_private.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), None, self.backend)
            with open(f"{self.keys_dir}/{username}_public.pem", "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read(), self.backend)
            
            cert_path = f"{self.keys_dir}/{username}_cert.pem"
            if os.path.exists(cert_path):
                with open(cert_path, "r") as f:
                    self.certificate = f.read()
            
            print(f"Keys loaded for {username}")
            return True
        except FileNotFoundError:
            print(f"No keys found for {username}")
            return False
    
    def get_anonymous_id(self):
        if not self.public_key:
            return None
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(pub_pem).hexdigest()[:16]

    # ==================== ENCRIPTACAO DE MENSAGENS ====================

    def encrypt_message(self, message: str, public_key_pem: str) -> str:
        """Cifra uma string usando uma chave pública externa"""
        try:
            pub_key = serialization.load_pem_public_key(
                public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
                backend=self.backend
            )
            encrypted = pub_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted.hex()
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, ciphertext_hex: str) -> str:
        """Decifra uma mensagem hex usando a MINHA chave privada"""
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
if __name__ == "__main__":
    print("=== CryptoManager Test ===")