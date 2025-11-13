import socket
import threading
import json
import time
from typing import Callable, List, Optional
from models import Auction, Bid, P2PMessage


class P2PNetwork:
    def __init__(self, host="0.0.0.0", port=0):
        # port=0 → o sistema escolhe uma porta livre automaticamente
        self.host = host
        self.port = port
        self.peers = []  # Lista de (ip, port) dos outros clientes
        self.socket = None 
        self.running = False
        
        # Callbacks para processar mensagens recebidas
        self.on_auction_received = None
        self.on_bid_received = None
        
    #Inicia o servidor P2P
    def start(self):
        #Criar o socket TCP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #Permitir reusar portas
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #Associar o socket ao IP:porta
        self.socket.bind((self.host, self.port))
        
        # Descobre a porta atribuída automaticamente
        self.port = self.socket.getsockname()[1]
        
        self.socket.listen(5)
        self.running = True
        
        print(f"P2P Node started on {self.host}:{self.port}")
        
        # Thread para aceitar conexões
        accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        accept_thread.start()

    #Para o servidor P2P
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        print("P2P Node stopped")
    
    def _accept_connections(self):
        #Aceita conexões de outros peers (thread separada)
        #Utilizamos threads para receber varios clients ao mesmo tempo
        while self.running: #loop infinito enquanto esta ativo
            try:
                client_socket, address = self.socket.accept()
                print(f"New connection from {address}")
                
                # Thread para lidar com o cliente
                handler_thread = threading.Thread(
                    target=self._handle_peer,
                    args=(client_socket, address),
                    daemon=True
                )
                handler_thread.start()
                
            except Exception as e:
                if self.running:
                    print(f" Error accepting connection: {e}")
    
    def _handle_peer(self, client_socket, address):
        #Processa mensagens recebidas de um peer
        try:
            # Recebe dados
            data = b""
            while True:
                chunk = client_socket.recv(4096) # Recebe até 4KB
                if not chunk:
                    break
                data += chunk
                
                # Verifica se recebeu a mensagem completa (termina com \n)
                if b"\n" in data:
                    break
            
            if not data:
                return
            
            # Converte JSON → Python dict
            message_dict = json.loads(data.decode('utf-8'))
            #Criar objeto P2PMessage
            message = P2PMessage(
                msg_type=message_dict["type"],
                data=message_dict["data"]
            )
            
            print(f"Received {message.type} from {address}")
            
            # Processa mensagem
            self._process_message(message)
            
        except Exception as e:
            print(f"Error handling peer {address}: {e}")
        finally:
            client_socket.close()
    
    def _process_message(self, message: P2PMessage):
        #Processa mensagem recebida baseado no tipo
        if message.type == "auction":
            auction = Auction.from_dict(message.data)
            if self.on_auction_received:
                self.on_auction_received(auction)
                
        elif message.type == "bid":
            bid = Bid.from_dict(message.data)
            if self.on_bid_received:
                self.on_bid_received(bid)
    
    # ==================== ENVIAR MENSAGENS ====================
    
    def broadcast_auction(self, auction: Auction):
        #Envia anúncio de leilão para todos os peers
        message = P2PMessage(
            msg_type="auction",
            data=auction.to_dict() # Converte Auction → dict
        )
        #Enviar para todos os peers
        self._broadcast(message)
        print(f"Broadcasted auction: {auction.item}")
    
    def broadcast_bid(self, bid: Bid):
        #Envia bid para todos os peers
        message = P2PMessage(
            msg_type="bid",
            data=bid.to_dict()
        )
        self._broadcast(message)
        print(f"Broadcasted bid: {bid.value}€")
    
    def _broadcast(self, message: P2PMessage):
        #Envia mensagem para todos os peers conhecidos
        message_json = json.dumps(message.to_dict()) + "\n" # Adiciona \n para indicar fim da mensagem
        message_bytes = message_json.encode('utf-8')
        
        failed_peers = []
        
        for peer_host, peer_port in self.peers:
            try:
                # Conecta ao peer
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.settimeout(5)  # Timeout de 5 segundos
                peer_socket.connect((peer_host, peer_port))
                
                # Envia mensagem
                peer_socket.sendall(message_bytes)
                peer_socket.close()
                
            except Exception as e:
                print(f"Failed to send to {peer_host}:{peer_port}: {e}")
                failed_peers.append((peer_host, peer_port))
        
        # Remove peers que falharam
        for peer in failed_peers:
            self.peers.remove(peer)
    
    # ==================== GESTÃO DE PEERS ====================
    
    def add_peer(self, host: str, port: int):
        #Adiciona um novo peer à lista
        peer = (host, port)
        if peer not in self.peers and peer != (self.host, self.port):
            self.peers.append(peer)
            print(f"Added peer: {host}:{port}")
    
    def remove_peer(self, host: str, port: int):
        #Remove um peer da lista
        peer = (host, port)
        if peer in self.peers:
            self.peers.remove(peer)
            print(f"Removed peer: {host}:{port}")
    
    def get_peers(self) -> List[tuple]:
        #Retorna lista de peers conectados
        return self.peers.copy()
    
    def register_callbacks(self, on_auction=None, on_bid=None):
        #Define funções callback para processar mensagens
        if on_auction:
            self.on_auction_received = on_auction
        if on_bid:
            self.on_bid_received = on_bid