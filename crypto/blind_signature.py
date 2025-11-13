"""
Implementação de RSA Blind Signatures
Permite ao servidor assinar mensagens sem conhecer o seu conteúdo

Protocolo:
1. Cliente: gera mensagem m, blinding factor r
2. Cliente: calcula m' = blind(m, r, public_key) 
3. Cliente -> Servidor: m'
4. Servidor: calcula s' = sign(m', private_key)
5. Servidor -> Cliente: s'
6. Cliente: calcula s = unblind(s', r, public_key)
7. Cliente pode agora usar (m, s) como token anónimo
8. Qualquer um pode verificar que s é assinatura válida de m usando public_key
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import secrets
import hashlib


class BlindSignature:
    """Implementação de RSA Blind Signatures"""
    
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.backend = default_backend()
    
    def _bytes_to_int(self, b):
        """Converte bytes para inteiro"""
        return int.from_bytes(b, byteorder='big')
    
    def _int_to_bytes(self, i, length):
        """Converte inteiro para bytes"""
        return i.to_bytes(length, byteorder='big')
    
    def _hash_message(self, message):
        """Hash da mensagem (SHA-256)"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(message)
        return digest.finalize()
    
    def generate_blinding_factor(self, public_key):
        """
        Gera fator de blinding aleatório r
        r deve ser coprimo com n (módulo da chave pública)
        """
        n = public_key.public_numbers().n
        e = public_key.public_numbers().e
        
        # Gerar r aleatório < n
        r = secrets.randbelow(n - 1) + 1
        
        # r^e mod n
        r_e = pow(r, e, n)
        
        return r, r_e
    
    def blind(self, message, public_key):
        """
        Cliente: cega a mensagem antes de enviar ao servidor
        
        Args:
            message: mensagem original (bytes ou string)
            public_key: chave pública do servidor
        
        Returns:
            (blinded_message, blinding_factor, message_hash)
        """
        # Hash da mensagem
        m_hash = self._hash_message(message)
        m = self._bytes_to_int(m_hash)
        
        # Parâmetros da chave pública
        n = public_key.public_numbers().n
        e = public_key.public_numbers().e
        
        # Gerar blinding factor
        r, r_e = self.generate_blinding_factor(public_key)
        
        # m' = m * r^e mod n (mensagem cega)
        m_blinded = (m * r_e) % n
        
        return m_blinded, r, m_hash
    
    def blind_sign(self, blinded_message, private_key):
        """
        Servidor: assina mensagem cega (sem saber o conteúdo)
        
        Args:
            blinded_message: mensagem cega (inteiro)
            private_key: chave privada do servidor
        
        Returns:
            blinded_signature (inteiro)
        """
        # Parâmetros da chave privada
        n = private_key.private_numbers().public_numbers.n
        d = private_key.private_numbers().d
        
        # s' = (m')^d mod n
        s_blinded = pow(blinded_message, d, n)
        
        return s_blinded
    
    def unblind(self, blinded_signature, blinding_factor, public_key):
        """
        Cliente: remove blinding para obter assinatura real
        
        Args:
            blinded_signature: assinatura cega recebida do servidor
            blinding_factor: r usado no blinding
            public_key: chave pública do servidor
        
        Returns:
            signature (assinatura real)
        """
        n = public_key.public_numbers().n
        
        # Calcular inverso modular de r
        r_inv = pow(blinding_factor, -1, n)
        
        # s = s' * r^(-1) mod n
        signature = (blinded_signature * r_inv) % n
        
        return signature
    
    def verify(self, message, signature, public_key):
        """
        Qualquer um pode verificar a assinatura
        
        Args:
            message: mensagem original (bytes ou string)
            signature: assinatura (inteiro)
            public_key: chave pública do servidor
        
        Returns:
            True se válida, False caso contrário
        """
        # Hash da mensagem
        m_hash = self._hash_message(message)
        m = self._bytes_to_int(m_hash)
        
        # Parâmetros da chave pública
        n = public_key.public_numbers().n
        e = public_key.public_numbers().e
        
        # Verificar: m == s^e mod n
        m_recovered = pow(signature, e, n)
        
        return m == m_recovered
    
    def signature_to_token(self, message_hash, signature):
        """
        Converte assinatura para token (formato string)
        Token = message_hash + signature (ambos em hex)
        """
        sig_bytes = self._int_to_bytes(signature, self.key_size // 8)
        token = message_hash.hex() + ":" + sig_bytes.hex()
        return token
    
    def token_to_signature(self, token):
        """
        Parse token para extrair message_hash e signature
        """
        parts = token.split(":")
        if len(parts) != 2:
            raise ValueError("Invalid token format")
        
        message_hash = bytes.fromhex(parts[0])
        signature = self._bytes_to_int(bytes.fromhex(parts[1]))
        
        return message_hash, signature
    
    def verify_token(self, token, public_key):
        """
        Verifica se um token é válido
        (usado pelo servidor ao receber anúncios/bids)
        """
        try:
            message_hash, signature = self.token_to_signature(token)
            
            # Verificar assinatura
            m = self._bytes_to_int(message_hash)
            n = public_key.public_numbers().n
            e = public_key.public_numbers().e
            m_recovered = pow(signature, e, n)
            
            return m == m_recovered
        except Exception as e:
            print(f"Token verification error: {e}")
            return False


# ==================== FLUXO COMPLETO ====================

def demo_blind_signature_flow():
    """Demonstração do protocolo completo"""
    print("=== BLIND SIGNATURE PROTOCOL DEMO ===\n")
    
    # Setup: Servidor gera chaves
    print("1. Server generates RSA keypair...")
    server_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    server_public = server_private.public_key()
    print("   ✓ Server keys ready\n")
    
    bs = BlindSignature()
    
    # Cliente quer obter token anónimo
    print("2. Client wants anonymous token...")
    message = "ANONYMOUS_TOKEN_REQUEST_" + secrets.token_hex(16)
    print(f"   Original message: {message[:40]}...\n")
    
    # Cliente: Blind
    print("3. Client blinds the message...")
    blinded_msg, r, msg_hash = bs.blind(message, server_public)
    print(f"   Blinded message: {blinded_msg}")
    print(f"   (Server cannot see original)\n")
    
    # Cliente -> Servidor: envia blinded_msg
    print("4. Client -> Server: blinded message\n")
    
    # Servidor: Assina sem conhecer conteúdo
    print("5. Server signs the blinded message...")
    blinded_sig = bs.blind_sign(blinded_msg, server_private)
    print(f"   Blinded signature: {blinded_sig}\n")
    
    # Servidor -> Cliente: envia blinded_sig
    print("6. Server -> Client: blinded signature\n")
    
    # Cliente: Unblind
    print("7. Client unblinds the signature...")
    signature = bs.unblind(blinded_sig, r, server_public)
    print(f"   Real signature: {signature}\n")
    
    # Cliente cria token
    print("8. Client creates anonymous token...")
    token = bs.signature_to_token(msg_hash, signature)
    print(f"   Token: {token[:60]}...\n")
    
    # Verificação: Qualquer um pode verificar o token
    print("9. Anyone can verify the token is valid...")
    valid = bs.verify(message, signature, server_public)
    print(f"   ✓ Token is valid: {valid}\n")
    
    # Verificação alternativa usando só o token
    print("10. Verify using only the token...")
    valid2 = bs.verify_token(token, server_public)
    print(f"    ✓ Token verification: {valid2}\n")
    
    # Importante: Servidor NÃO conhece a mensagem original!
    print("=== PRIVACY CHECK ===")
    print("Server never saw:", message)
    print("Server only signed a blinded version")
    print("But token is verifiable by anyone! ✓")


if __name__ == "__main__":
    demo_blind_signature_flow()