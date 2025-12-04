# Módulo de comunicação com o servidor central
import socket
import json
import ssl  # Necessário para TLS/SSL
from typing import Optional, Dict, List

# Configuração do servidor - Usar o IP real do Servidor (Mac)
SERVER_HOST = 'localhost'  # Alterar para o IP do servidor real 
SERVER_PORT = 9999

class ServerClient:
    # Cliente para comunicação com o servidor central
    
    def __init__(self, server_host=SERVER_HOST, server_port=SERVER_PORT):
        self.server_host = server_host
        self.server_port = server_port
    
    def request(self, action: str, data: dict = {}) -> dict:
        """Envia pedido ao servidor via SSL/TLS e retorna resposta"""
        
        SOCKET_TIMEOUT = 10 
        
        try:
            # 1. Cria contexto SSL (sem verificação de CA para ambiente de desenvolvimento)
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='../ca_cert.pem') 
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # 2. Cria socket normal
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            
            # 3. Envolve o socket com SSL/TLS (O PASSO CRÍTICO)
            wrapped_socket = ssl_context.wrap_socket(s, server_hostname=self.server_host)
            
            # 4. Conecta
            wrapped_socket.connect((self.server_host, self.server_port))
            
            message = {'action': action, **data}
            wrapped_socket.send(json.dumps(message).encode('utf-8'))
            
            # 5. Recebe resposta e decodifica
            response = json.loads(wrapped_socket.recv(1024 * 64).decode('utf-8'))
            wrapped_socket.close()
            
            return response
        
        except Exception as e:
            # Captura o erro e retorna um formato JSON
            return {'status': 'error', 'message': str(e)}

    # Wrapper para chamadas que vêm do main.py (como get_blind_key)
    def send_request(self, full_payload: dict) -> dict:
        action = full_payload.get('action')
        data = {k: v for k, v in full_payload.items() if k != 'action'}
        return self.request(action, data)
    
    # ========== Funções de autenticação (TODAS USAM self.request) ==========
    
    def register_user(self, username: str, public_key: str, 
                     ip: str, port: int, password: str, signature=None) -> dict:
        payload = {
            'username': username,
            'public_key': public_key,
            'ip': ip,
            'port': port,
            'password': password
        }
        if signature:
            payload['signature'] = signature
        return self.request('register', payload)
    
    def login_user(self, username, password, nonce_solution=None):
        payload ={
            'username': username,
            'password': password
        }
        if nonce_solution:
            payload['nonce_solution'] = nonce_solution
        return self.request('login', payload)
    
    def get_login_challenge(self, username):
        return self.request('get_challenge', {'username': username})

    def get_ca_certificate(self) -> Optional[str]:
        response = self.request('get_ca_cert')
        if response.get('status') == 'success':
            return response.get('ca_certificate')
        return None
    
    def update_user_address(self, user_id, ip, port):
        return self.request('update_address', {
            'user_id': user_id,
            'ip': ip,
            'port': port
        })
    
    # ========== Funções de descoberta P2P ==========
    
    def get_users_list(self) -> List[dict]:
        response = self.request('get_users')
        if response.get('status') == 'success':
            return response.get('users', [])
        return []
    
    # ========== Funções de anonimato ==========
    
    def get_blind_token(self, blinded_message: str) -> Optional[dict]:
        response = self.request('get_blind_token', {
            'blinded_message': blinded_message
        })
        if response.get('status') == 'success':
            return response
        return None
    
    def verify_token(self, token_hash: str) -> bool:
        response = self.request('verify_token', {
            'token_hash': token_hash
        })
        return response.get('status') == 'success'
    
    # ========== Funções de timestamping ==========
    
    def request_timestamp(self, bid_data: str) -> Optional[dict]:
        response = self.request('timestamp', {
            'bid_data': bid_data
        })
        if response.get('status') == 'success':
            return response
        return None
    
    def store_identity_blob(self, auction_id: str, anonymous_token: str, encrypted_identity_blob: str) -> dict:
        #Envia o envelope de identidade cifrado para o Notário para custódia.
        return self.request('store_identity_blob', { 
            'auction_id': auction_id,
            'anonymous_token': anonymous_token,
            'encrypted_identity_blob': encrypted_identity_blob
        })

# ========== Funções de conveniência ==========

def quick_register(username: str, public_key: str, 
                  client_ip: str, client_port: int) -> dict:
    client = ServerClient()
    return client.register_user(username, public_key, client_ip, client_port)

def quick_get_users() -> List[dict]:
    client = ServerClient()
    return client.get_users_list()

def quick_timestamp(bid_data: str) -> Optional[dict]:
    client = ServerClient()
    return client.request_timestamp(bid_data)

