#Módulo de comunicação com o servidor central
import socket
import json
from typing import Optional, Dict, List

# Configuração do servidor
SERVER_HOST = '192.168.1.83'
SERVER_PORT = 9999

class ServerClient:
    #Cliente para comunicação com o servidor central
    
    def __init__(self, server_host=SERVER_HOST, server_port=SERVER_PORT):
        self.server_host = server_host
        self.server_port = server_port
    
    def _send_request(self, action: str, data: dict = {}) -> dict:
        #Envia pedido ao servidor e retorna resposta
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.server_host, self.server_port))
            
            message = {'action': action, **data}
            s.send(json.dumps(message).encode('utf-8'))
            
            response = json.loads(s.recv(65536).decode('utf-8'))
            s.close()
            
            return response
        
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    # ========== Funções de autenticação ==========
    
    def register_user(self, username: str, public_key: str, 
                     ip: str, port: int) -> dict:
        """
        Regista novo utilizador no servidor
        
        Args:
            username: Nome de utilizador único
            public_key: Chave pública RSA em formato PEM
            ip: Endereço IP do cliente
            port: Porta P2P do cliente
        
        Returns:
            dict com:
                - status: 'success' ou 'error'
                - user_id: ID único do utilizador
                - certificate: Certificado X.509 emitido pela CA
                - ca_certificate: Certificado da CA
        """
        return self._send_request('register', {
            'username': username,
            'public_key': public_key,
            'ip': ip,
            'port': port
        })
    
    def login_user(self, username, password):
        #Faz login no servidor
        return self._send_request('login', {  
            'username': username,
            'password': password
        })
    
    def get_ca_certificate(self) -> Optional[str]:
        #Obtém certificado da Certificate Authority
        response = self._send_request('get_ca_cert')
        if response.get('status') == 'success':
            return response.get('ca_certificate')
        return None
    
    def update_user_address(self, user_id, ip, port):
        #Atualiza IP e porta do utilizador no servidor
        return self._send_request('update_address', {
            'user_id': user_id,
            'ip': ip,
            'port': port
        })
    
    # ========== Funções de descoberta P2P ==========
    
    def get_users_list(self) -> List[dict]:
        #Obtém lista de todos os utilizadores registados
        response = self._send_request('get_users')
        if response.get('status') == 'success':
            return response.get('users', [])
        return []
    
    # ========== Funções de anonimato ==========
    
    def get_blind_token(self, blinded_message: str) -> Optional[dict]:
        #Obtém token cego para anonimato (blind signature)
        response = self._send_request('get_blind_token', {
            'blinded_message': blinded_message
        })
        if response.get('status') == 'success':
            return response
        return None
    
    def verify_token(self, token_hash: str) -> bool:
        #Verifica se um token anónimo é válido
        response = self._send_request('verify_token', {
            'token_hash': token_hash
        })
        return response.get('status') == 'success'
    
    # ========== Funções de timestamping ==========
    
    def request_timestamp(self, bid_data: str) -> Optional[dict]:
        #Pede timestamp confiável ao servidor
        response = self._send_request('timestamp', {
            'bid_data': bid_data
        })
        if response.get('status') == 'success':
            return response
        return None


# ========== Funções de conveniência ==========

def quick_register(username: str, public_key: str, 
                  client_ip: str, client_port: int) -> dict:
    #Atalho para registar utilizador
    client = ServerClient()
    return client.register_user(username, public_key, client_ip, client_port)

def quick_get_users() -> List[dict]:
    #Atalho para obter lista de utilizadores
    client = ServerClient()
    return client.get_users_list()

def quick_timestamp(bid_data: str) -> Optional[dict]:
    #Atalho para obter timestamp
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
