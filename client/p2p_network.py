import socket
import threading
import json
import time
from typing import Callable, List, Optional
from models import Auction, Bid, P2PMessage


class P2PNetwork:
    def __init__(self, host='0.0.0.0', port=0, database=None):
        # port=0. o sistema escolhe uma porta livre automaticamente
        self.db = database
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
        #Inicia o servidor P2P 
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        
        self.port = self.socket.getsockname()[1]
        
        self.socket.listen(5)
        self.running = True
        
        print(f"P2P Node started on {self.host}:{self.port}")
        
        accept_thread = threading.Thread(target=self._accept_connections, daemon=False)
        accept_thread.start()

    #Para o servidor P2P
    def stop(self):
        #Para o servidor P2P
        self.running = False
        time.sleep(1.5)  # Dá tempo para threads terminarem
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("P2P Node stopped")
    
    def _accept_connections(self):
        #Aceita conexões de outros peers (thread separada)
        while self.running:
            try:
                # Define timeout para não bloquear forever
                self.socket.settimeout(1.0)  
                
                try:
                    client_socket, address = self.socket.accept()
                except socket.timeout:
                    continue  # Volta ao loop, verifica self.running
                
                print(f"New connection from {address}")
                
                # Thread para lidar com este cliente
                handler_thread = threading.Thread(
                    target=self._handle_peer,
                    args=(client_socket, address),
                    daemon=False  
                )
                handler_thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
        
    def _handle_peer(self, client_socket, address):
        #Processa mensagens recebidas de um peer
        try:
            buffer = ""
            
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                
                buffer += chunk.decode('utf-8')
                
                # Processa todas as mensagens completas no buffer
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    
                    if not line.strip():
                        continue
                    
                    try:
                        message_dict = json.loads(line)
                        msg_type = message_dict.get("type")
                        
                        print(f"Received {msg_type} from {address}")
                        
                        # Processa diferentes tipos de mensagem:
                        
                        if msg_type == "sync_request":
                            print(f"Peer {address} pediu sincronização")
                            requester_info = message_dict["data"].get("requester", "")
                            if requester_info and ":" in requester_info:
                                host, port = requester_info.split(":")
                                self.send_sync_response(host, int(port))
                        
                        elif msg_type == "sync_response":
                            # Recebe leilões e bids na sincronização
                            sync_data = message_dict["data"]
                            print(f"Sincronização recebida")
                            
                            if self.on_sync_received:
                                self.on_sync_received(sync_data)
                        
                        elif msg_type == "auction":
                            # Novo leilão broadcast
                            auction = Auction.from_dict(message_dict["data"])
                            if self.on_auction:
                                self.on_auction(auction)
                        
                        elif msg_type == "bid":
                            # Novo bid broadcast
                            bid = Bid.from_dict(message_dict["data"])
                            if self.on_bid:
                                self.on_bid(bid)

                        elif msg_type == "auction_closed":
                            # Mensagem que anuncia o fim de um leilão e o hash do vencedor
                            print(f"Recebido anúncio de fecho de leilão de {address}")
                            data = message_dict["data"]
                            if self.on_auction_closed:
                                self.on_auction_closed(data)
                        
                        elif msg_type == "REVEAL_INFO": 
                            # Mensagem que anuncia a revelação do Vencedor e Vendedor
                            print(f"Received reveal info broadcast from {address}")
                            data = message_dict["data"]
                            if hasattr(self, 'on_reveal') and self.on_reveal:
                                self.on_reveal(data)
                        
                        else:
                            print(f"Tipo de mensagem desconhecido: {msg_type}")
                    
                    except json.JSONDecodeError as e:
                        print(f"JSON inválido de {address}: {e}")
                    except KeyError as e:
                        print(f"Mensagem incompleta de {address}: falta {e}")
                    except Exception as e:
                        print(f"Erro ao processar mensagem: {e}")
                        import traceback
                        traceback.print_exc()
            
        except Exception as e:
            print(f"Erro no handler de {address}: {e}")
        finally:
            client_socket.close()
    
    
    
    # ==================== ENVIAR MENSAGENS ====================
    
    def broadcast_auction(self, auction: Auction):
        #Envia anúncio de leilão para todos os peers
        message = P2PMessage(
            msg_type="auction",
            data=auction.to_dict() # Converte Auction -> dict
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
        if not self.peers:
            print("No peers to broadcast to")
            return
        
        try:
            message_json = json.dumps(message.to_dict()) + "\n"
            message_bytes = message_json.encode('utf-8')
        except Exception as e:
            print(f"Error encoding message: {e}")
            return
        
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
                
                print(f"Sent to {peer_host}:{peer_port}")
                
            except Exception as e:
                print(f"Failed to send to {peer_host}:{peer_port}: {e}")
                failed_peers.append((peer_host, peer_port))
        
        # Remove peers que falharam
        for peer in failed_peers:
            if peer in self.peers:
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
    
    def register_callbacks(self, on_auction=None, on_bid=None, on_sync_received=None, on_auction_closed=None, on_reveal=None):
        #Define funções callback para processar mensagens
        if on_auction:
            self.on_auction_received = on_auction
            self.on_auction = on_auction  
        if on_bid:
            self.on_bid_received = on_bid
            self.on_bid = on_bid  
        if on_sync_received:
            self.on_sync_received = on_sync_received
        if on_auction_closed:
            self.on_auction_closed = on_auction_closed
        if on_reveal:
            self.on_reveal = on_reveal

    #Pedir sincronização de leilões a um peer
    def request_sync_from_peer(self, peer_host, peer_port):
        #Pede a um peer que envie todos os seus leilões
        try:
            import socket as sock
            try:
                s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                my_ip = s.getsockname()[0]
                s.close()
            except:
                my_ip = '127.0.0.1'
            
            message = P2PMessage(
                msg_type="sync_request",
                data={"requester": f"{my_ip}:{self.port}"}  
            )
            
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.settimeout(5)
            peer_socket.connect((peer_host, peer_port))
            
            message_json = json.dumps(message.to_dict()) + "\n"
            peer_socket.sendall(message_json.encode('utf-8'))
            peer_socket.close()
            
            print(f"Sync request sent to {peer_host}:{peer_port}")
            
        except Exception as e:
            print(f"Erro ao pedir sync: {e}")
            import traceback
            traceback.print_exc()

    def send_sync_response(self, peer_host, peer_port):
        #Envia todos os nossos leilões para um peer que pediu
        try:
            if not self.db:
                print("Database not available for sync")
                return
                
            auctions = self.db.get_all_auctions()
            bids = self.db.get_my_bids() if hasattr(self.db, 'get_my_bids') else []
            
            auctions_data = [auction.to_dict() for auction in auctions]
            bids_data = [bid.to_dict() for bid in bids]
            
            message = P2PMessage(
                msg_type="sync_response",
                data={
                    "auctions": auctions_data,
                    "bids": bids_data
                }
            )
            
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.settimeout(5)
            peer_socket.connect((peer_host, peer_port))
            
            message_json = json.dumps(message.to_dict()) + "\n"
            peer_socket.sendall(message_json.encode('utf-8'))
            peer_socket.close()
            
            print(f"Sent {len(auctions)} auctions to {peer_host}:{peer_port}")
            
        except Exception as e:
            print(f"Erro ao enviar sync: {e}")
            import traceback
            traceback.print_exc()
    
    def broadcast_auction_closed(self, auction_id, winning_token_hash, seller_contact):
        #Avisa a rede que o leilão fechou e quem ganhou (pelo hash do token)
        message = P2PMessage(
            msg_type="auction_closed",
            data={
                "auction_id": auction_id,
                "winning_token": winning_token_hash,
                "seller_contact": seller_contact 
            }
        )
        self._broadcast(message)
        print(f"Broadcasted CLOSING of auction {auction_id}")