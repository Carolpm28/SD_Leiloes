import secrets
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class Challenge_Manager:
    def __init__ (self , expiration_time = 60):
        # armazena os desafios
        self.challenges = {}
        self.expiration_time = expiration_time  # tempo em segundos para expiração do desafio

    def generate_challenge(self, username, public_key_pem):
        """
        Gera um nonce, cifra-o com a chave pública do user e guarda-o.
        Retorna: O desafio cifrado em Hex.
        """
        
        #gerar nonce
        nonce = str(secrets.randbits(128)) 

        #calcula expiracao
        expiration = time.time() + self.expiration_time

        #guardar no registo
        self.challenges[username] = {
            'nonce': nonce,
            'expires': expiration
        }

        #carregar chave publica e encriptar
        try:
            pub_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            encrypted_nonce = pub_key.encrypt(
                nonce.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_nonce.hex()
        except Exception as e:
            print(f"Erro ao encriptar o nonce: {e}")
            return None
        
    def verify_response(self, username, response):
        """
        Verifica se a resposta ao desafio é correta e não expirou.
        Retorna: True se correto, False caso contrário.
        """
        if username not in self.challenges:
            return False
        
        challenge = self.challenges[username]
        
        #verificar expiracao
        if time.time() > challenge['expires']:
            del self.challenges[username]
            return False
        
        #verificar nonce
        if response == challenge['nonce']:
            del self.challenges[username]
            return True
        else:
            return False