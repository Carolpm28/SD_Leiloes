"""
Módulo para geração e gestão de chaves criptográficas
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


class KeyManager:
    """Gestor de chaves RSA e AES"""
    
    def __init__(self, key_size=4096):
        self.key_size = key_size
        self.backend = default_backend()
    
    def generate_rsa_keypair(self):
        """
        Gera um par de chaves RSA (pública e privada)
        Returns: (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_private_key(self, private_key, filename, password=None):
        """Guarda chave privada em ficheiro (encriptada se password fornecida)"""
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
    
    def save_public_key(self, public_key, filename):
        """Guarda chave pública em ficheiro"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
    
    def load_private_key(self, filename, password=None):
        """Carrega chave privada de ficheiro"""
        with open(filename, 'rb') as f:
            pem_data = f.read()
        
        pwd = password.encode() if password else None
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=pwd,
            backend=self.backend
        )
        return private_key
    
    def load_public_key(self, filename):
        """Carrega chave pública de ficheiro"""
        with open(filename, 'rb') as f:
            pem_data = f.read()
        
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=self.backend
        )
        return public_key
    
    def public_key_to_pem(self, public_key):
        """Converte chave pública para PEM (string)"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def pem_to_public_key(self, pem_string):
        """Converte PEM (string) para chave pública"""
        return serialization.load_pem_public_key(
            pem_string.encode('utf-8'),
            backend=self.backend
        )


# Funções auxiliares para assinaturas digitais normais
def sign_data(private_key, data):
    """
    Assina dados com chave privada (RSA-PSS)
    Args:
        private_key: chave privada RSA
        data: bytes a assinar
    Returns: assinatura (bytes)
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, data, signature):
    """
    Verifica assinatura digital
    Args:
        public_key: chave pública RSA
        data: dados originais (bytes)
        signature: assinatura a verificar (bytes)
    Returns: True se válida, False caso contrário
    """
    try:
        public_key.verify(
            signature,
            data,
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


def encrypt_data(public_key, data):
    """
    Encripta dados com chave pública (RSA-OAEP)
    Args:
        public_key: chave pública RSA
        data: dados a encriptar (bytes, max ~470 bytes para RSA 4096)
    Returns: dados encriptados (bytes)
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_data(private_key, ciphertext):
    """
    Desencripta dados com chave privada
    Args:
        private_key: chave privada RSA
        ciphertext: dados encriptados (bytes)
    Returns: dados originais (bytes)
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# Teste rápido
if __name__ == "__main__":
    print("Testing KeyManager...")
    
    # Gerar par de chaves
    km = KeyManager(key_size=2048)  # 2048 para testes (mais rápido)
    priv, pub = km.generate_rsa_keypair()
    print("✓ Keypair generated")
    
    # Testar assinatura
    message = b"Test message for auction system"
    sig = sign_data(priv, message)
    valid = verify_signature(pub, message, sig)
    print(f"✓ Signature valid: {valid}")
    
    # Testar encriptação
    encrypted = encrypt_data(pub, b"Secret bid value")
    decrypted = decrypt_data(priv, encrypted)
    print(f"✓ Encryption/Decryption: {decrypted}")
    
    print("\nAll tests passed!")