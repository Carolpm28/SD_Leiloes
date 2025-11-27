# Módulo de comunicação com o servidor central
import socket
import json
from typing import Optional, Dict, List

# Configuração do servidor
SERVER_HOST = 'localhost'
SERVER_PORT = 9999

class ServerClient:
    # Cliente para comunicação com o servidor central
    
    def __init__(self, server_host=SERVER_HOST, server_port=SERVER_PORT):
        self.server_host = server_host
        self.server_port = server_port
    
    def _send_request(self, action: str, data: dict = {}) -> dict:
        # Envia pedido ao servidor e retorna resposta (Função Interna)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.server_host, self.server_port))
            
            message = {'action': action, **data}
            s.send(json.dumps(message).encode('utf-8'))
            
            # Buffer grande (65536) para garantir que recebemos chaves/certificados inteiros
            response = json.loads(s.recv(65536).decode('utf-8'))
            s.close()
            
            return response
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # ========== NOVA FUNÇÃO (A QUE FALTAVA) ==========
    def send_request(self, full_payload: dict) -> dict:
        """
        Wrapper público para enviar pedidos genéricos.
        Necessário para o main.py pedir a 'get_blind_key'.
        """
        action = full_payload.get('action')
        # Separa a 'action' do resto dos dados
        data = {k: v for k, v in full_payload.items() if k != 'action'}
        return self._send_request(action, data)
    # =================================================
    
    # ========== Funções de autenticação ==========
    
    def register_user(self, username: str, public_key: str, 
                     ip: str, port: int, password: str) -> dict:
        """Regista novo utilizador no servidor"""
        return self._send_request('register', {
            'username': username,
            'public_key': public_key,
            'ip': ip,
            'port': port,
            'password': password
        })
    
    def login_user(self, username, password):
        # Faz login no servidor
        return self._send_request('login', {  
            'username': username,
            'password': password
        })
    
    def get_ca_certificate(self) -> Optional[str]:
        # Obtém certificado da Certificate Authority
        response = self._send_request('get_ca_cert')
        if response.get('status') == 'success':
            return response.get('ca_certificate')
        return None
    
    def update_user_address(self, user_id, ip, port):
        # Atualiza IP e porta do utilizador no servidor
        return self._send_request('update_address', {
            'user_id': user_id,
            'ip': ip,
            'port': port
        })
    
    # ========== Funções de descoberta P2P ==========
    
    def get_users_list(self) -> List[dict]:
        # Obtém lista de todos os utilizadores registados
        response = self._send_request('get_users')
        if response.get('status') == 'success':
            return response.get('users', [])
        return []
    
    # ========== Funções de anonimato ==========
    
    def get_blind_token(self, blinded_message: str) -> Optional[dict]:
        # Obtém token cego para anonimato (blind signature)
        response = self._send_request('get_blind_token', {
            'blinded_message': blinded_message
        })
        if response.get('status') == 'success':
            return response
        return None
    
    def verify_token(self, token_hash: str) -> bool:
        # Verifica se um token anónimo é válido
        response = self._send_request('verify_token', {
            'token_hash': token_hash
        })
        return response.get('status') == 'success'
    
    # ========== Funções de timestamping ==========
    
    def request_timestamp(self, bid_data: str) -> Optional[dict]:
        # Pede timestamp confiável ao servidor
        response = self._send_request('timestamp', {
            'bid_data': bid_data
        })
        if response.get('status') == 'success':
            return response
        return None


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


# ========== Exemplo de uso ==========

if __name__ == "__main__":
    # Exemplo 1: Obter certificado da CA
    client = ServerClient()
    ca_cert = client.get_ca_certificate()
    if ca_cert:
        print("CA Certificate obtained")
    
    # Exemplo 2: Listar utilizadores
    users = client.get_users_list()
    print(f"Found {len(users)} registered users")
    
    # Exemplo 3: Pedir timestamp para um lance
    timestamp_info = client.request_timestamp("auction_123|100.50|token_xyz")
    if timestamp_info:
        print(f"Timestamp: {timestamp_info['timestamp']}")