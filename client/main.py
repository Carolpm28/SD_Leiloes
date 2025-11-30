#Aplicação principal do cliente de leilões. Coordena: Database, P2P Network, Crypto e API REST
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime
import threading  
import time
import atexit
import hashlib  
import secrets  
import uuid     
import requests

from database import Database
from p2p_network import P2PNetwork
from models import Auction, Bid
from crypto_manager import CryptoManager
from server_client import ServerClient 

import signal
import sys
import atexit

from crypto.blind_signature import BlindSignature
from crypto.keys import KeyManager

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# ==================== INICIALIZAÇÃO ====================

app = Flask(__name__)
CORS(app)  # Permite requests da frontend

# Componentes
db = Database("auction_client.db")
network = P2PNetwork(port=6000, database=db)
crypto = CryptoManager()
server = ServerClient()  

# Estado global
my_user_id = None  # ID do utilizador (definir depois)
server_blind_pub_key = None

print("Starting Auction Client...")

# Carregar chave pública do certificado CA
try:
    
    # Caminho para o certificado CA
    ca_cert_path = os.path.join(os.path.dirname(__file__), '..', 'ca_cert.pem')
    
    if os.path.exists(ca_cert_path):
        # Carregar certificado X.509
        with open(ca_cert_path, 'rb') as f:
            cert_data = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        public_key = cert.public_key()  # Extrair chave pública
        
        bs = BlindSignature()
        print("Blind signature verification ready")
    else:
        print(f"CA certificate not found at: {ca_cert_path}")
        print("Token verification disabled")
        bs = None
        public_key = None
        
        
except Exception as e:
    print(f"Error loading CA certificate: {e}")
    import traceback
    traceback.print_exc()
    bs = None
    public_key = None


def get_or_update_blind_key():
    """Obtém a chave pública de Blind Signature do servidor se ainda não existir"""
    global server_blind_pub_key  # <--- Fundamental para aceder à variável global
    
    # Se já tivermos a chave, não precisamos de pedir novamente
    if server_blind_pub_key is not None:
        return True

    print("Fetching Server Blind Public Key...")
    try:
        # Envia pedido 'get_blind_key'
        response = server.send_request({'action': 'get_blind_key'})
        print(f"DEBUG - RESPOSTA DO SERVIDOR: {response}")
        
        if response and response.get('status') == 'success':
            key_pem = response['blind_public_key'].encode()
            server_blind_pub_key = serialization.load_pem_public_key(
                key_pem, 
                backend=default_backend()
            )
            print("Server Blind Key loaded successfully.")
            return True
        else:
            print("Failed to get blind key from server response")
            return False
    except Exception as e:
        print(f"Error fetching blind key: {e}")
        return False
    
# ==================== CALLBACKS P2P ====================

def on_auction_received(auction: Auction):
    # Debug: ver formato do token
    print(f"Token recebido (primeiros 100 chars): {auction.anonymous_token[:100] if auction.anonymous_token else 'None'}...")
    
    # 1. GARANTIR QUE TEMOS A CHAVE DE VERIFICAÇÃO (Blind Key)
    # Se o PC2 acabou de ligar, pode ainda não ter pedido esta chave ao servidor
    if not get_or_update_blind_key():
        print("Impossível verificar: Falha ao obter chave pública do servidor")
        return

    # 2. VERIFICAR USANDO A server_blind_pub_key
    if bs and server_blind_pub_key and auction.anonymous_token:
        try:
            if ':' not in auction.anonymous_token:
                print(f"Token sem ':' - formato inválido: {type(auction.anonymous_token)}")
            else:
                # MUDANÇA AQUI: Usa server_blind_pub_key em vez de public_key
                if not bs.verify_token(auction.anonymous_token, server_blind_pub_key):
                    print("Token inválido! Auction rejeitado.")
                    return
                print("Token verificado com sucesso")
        except Exception as e:
            print(f"Erro na verificação do token: {e}")
            import traceback
            traceback.print_exc()
    
    db.save_auction(auction, is_mine=False)
    print(f"Auction recebido: {auction.item}")


def on_bid_received(bid: Bid):
    # CORREÇÃO: Declarar global logo no início para evitar o SyntaxError
    global server_blind_pub_key
    
    print(f"Bid token (primeiros 100 chars): {bid.anonymous_token[:100] if bid.anonymous_token else 'None'}...")
    
    # 1. Garantir que temos uma chave para tentar verificar
    if not get_or_update_blind_key():
        print("Impossível verificar: Falha ao obter chave pública do servidor")
        return

    # 2. Tentar verificar
    if bs and server_blind_pub_key and bid.anonymous_token:
        try:
            if ':' not in bid.anonymous_token:
                print(f"Token sem ':' - formato: {type(bid.anonymous_token)}")
                return

            # Tenta verificar com a chave atual
            is_valid = bs.verify_token(bid.anonymous_token, server_blind_pub_key)
            
            # Se falhar, a chave pode estar obsoleta (Server reiniciou). Forçamos refresh.
            if not is_valid:
                print("Verificação falhou. A tentar atualizar a chave do servidor...")
                
                # Força a função get_or_update a ir buscar nova chave
                server_blind_pub_key = None  
                
                if get_or_update_blind_key():
                    # Tenta verificar novamente com a chave fresca
                    is_valid = bs.verify_token(bid.anonymous_token, server_blind_pub_key)
                    if is_valid:
                        print("Sucesso após atualização da chave!")
            
            if not is_valid:
                print("Token inválido (mesmo após refresh)! Bid rejeitado.")
                return
                
            print("Token verificado com sucesso")

        except Exception as e:
            print(f"Erro: {e}")
            import traceback
            traceback.print_exc()
            return # Se deu erro, não guarda
    
    db.save_bid(bid, is_mine=False)
    print(f"Bid recebido: €{bid.value:.2f}")
 
    


def on_sync_received(sync_data):
    #Callback quando recebe sincronização de leilões E BIDS
    auctions_data = sync_data.get("auctions", [])
    bids_data = sync_data.get("bids", [])  
    
    print(f"Sincronização: {len(auctions_data)} leilões, {len(bids_data)} bids")
    
    # Sincronizar leilões
    synced_auctions = 0
    for auction_dict in auctions_data:
        try:
            auction = Auction.from_dict(auction_dict)
            if not db.get_auction(auction.auction_id):
                db.save_auction(auction,is_mine=False)
                print(f" Leilão: {auction.item}")
                synced_auctions += 1
        except Exception as e:
            print(f"Erro ao sincronizar leilão: {e}")
    
    # sincronizar bids
    synced_bids = 0
    for bid_dict in bids_data:
        try:
            bid = Bid.from_dict(bid_dict)
            # Verificar se já existe (comparar bid_id)
            existing_bids = db.get_bids_for_auction(bid.auction_id)
            if not any(b.bid_id == bid.bid_id for b in existing_bids):
                db.save_bid(bid, is_mine=False)
                print(f"Bid: €{bid.value} no leilão {bid.auction_id[:8]}...")
                synced_bids += 1
        except Exception as e:
            print(f"Erro ao sincronizar bid: {e}")
    
    print(f"Sincronização: {synced_auctions} leilões, {synced_bids} bids novos")




# ==================== API REST ====================

# --- SERVIR FRONTEND ---

@app.route('/')
def index():
    #Serve a página principal (index.html)
    current_dir = os.path.dirname(os.path.abspath(__file__))
    ui_dir = os.path.join(current_dir, 'ui')
    return send_from_directory(ui_dir, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    #Serve CSS, JS e outros ficheiros estáticos
    current_dir = os.path.dirname(os.path.abspath(__file__))
    ui_dir = os.path.join(current_dir, 'ui')
    return send_from_directory(ui_dir, filename)


# --- LEILÕES ---

@app.route('/api/auctions', methods=['GET'])
def get_auctions():
    #Retorna todos os leilões
    auctions = db.get_all_auctions()
    return jsonify([auction.to_dict() for auction in auctions])


@app.route('/api/auctions/active', methods=['GET'])
def get_active_auctions():
    #Retorna apenas leilões ativos (não fechados)
    auctions = db.get_active_auctions()
    return jsonify([auction.to_dict() for auction in auctions])


@app.route('/api/auctions/mine', methods=['GET'])
def get_my_auctions():
    #Retorna leilões que EU(utilizador) criei
    auctions = db.get_my_auctions()
    return jsonify([auction.to_dict() for auction in auctions])


@app.route('/api/auctions', methods=['POST'])
def create_auction():
    # Cria novo leilão com anonimato e Blind Signature corrigida
    
    # Validar autenticação
    if not crypto.user_id:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.json
    
    item = data.get('item')
    closing_date = data.get('closing_date')
    min_bid = data.get('min_bid')
    categoria = data.get('categoria')
    
    if not item or not closing_date:
        return jsonify({"error": "Item and closing date are required"}), 400
    
    try:
        print("\nRequesting anonymous token from server...")
        
        # 1. Garantir que temos a chave pública correta do servidor
        if not get_or_update_blind_key():
             return jsonify({"error": "Could not obtain server blind key"}), 500

        # 2. Gerar mensagem para o token
        message = f"AUCTION_{secrets.token_hex(16)}"
        
        # 3. Cegar a mensagem usando a chave de BLIND SIGNATURE (e não a da CA)
        # O 'server_blind_pub_key' garante que o módulo matemático n é compatível
        blinded_msg, r, m_hash = bs.blind(message, server_blind_pub_key)

        # 4. Pedir assinatura cega ao servidor (envia o número cego como string)
        token_response = server.get_blind_token(str(blinded_msg)) 

        if token_response and token_response.get('status') == 'success':
            blind_sig = int(token_response['blind_signature'])
            
            # 5. Remover cegueira (Unblind) usando a MESMA chave pública
            # Isto corrige o OverflowError porque os módulos n coincidem
            signature = bs.unblind(blind_sig, r, server_blind_pub_key)

            # 6. Criar token no formato "hash:signature"
            anonymous_token = bs.signature_to_token(m_hash, signature) 

            print(f"Token criado com sucesso: {anonymous_token[:50]}...")
        else:
            raise Exception("Server refused to sign blind token")
        
        # 7. Criar objeto Auction
        auction = Auction(
            item=item,
            closing_date=closing_date,
            min_bid=float(min_bid) if min_bid else None,
            categoria=categoria
        )

        auction.anonymous_token = anonymous_token
        auction.seller_anonymous_id = crypto.get_anonymous_id()
        
        # 8. Guardar na base de dados local
        db.save_auction(auction, is_mine=True)
        
        # 9. Broadcast P2P
        network.broadcast_auction(auction)
        
        print(f"Auction broadcasted anonymously: {item}")
        
        return jsonify({
            "auction_id": auction.auction_id,
            "item": auction.item,
            "closing_date": auction.closing_date,
            "min_bid": auction.min_bid,
            "anonymous_token": anonymous_token[:16] + "..."
        }), 201
        
    except Exception as e:
        print(f"Erro ao criar leilão: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/auctions/<auction_id>', methods=['GET'])
def get_auction(auction_id):
    #Retorna detalhes de um leilão específico
    auction = db.get_auction(auction_id)
    
    if not auction:
        return jsonify({"error": "Auction not found"}), 404
    
    return jsonify(auction.to_dict())


@app.route('/api/auctions/closed', methods=['GET'])
def get_closed_auctions():
    #Retorna leilões encerrados
    auctions = db.get_closed_auctions()
    return jsonify([auction.to_dict() for auction in auctions])


# --- BIDS ---

@app.route('/api/auctions/<auction_id>/bids', methods=['GET'])
def get_bids(auction_id):
    #Retorna todos os bids de um leilão
    bids = db.get_bids_for_auction(auction_id)
    return jsonify([bid.to_dict() for bid in bids])


@app.route('/api/auctions/<auction_id>/winner', methods=['GET'])
def get_winner(auction_id):
    #Retorna o bid vencedor de um leilão
    winner = db.get_winning_bid(auction_id)
    
    if not winner:
        return jsonify({"error": "No bids yet"}), 404
    
    return jsonify(winner.to_dict())


@app.route('/api/bids', methods=['POST'])
def create_bid():
    # Cria novo bid ANÓNIMO com blind signature corrigida
    data = request.json
    
    # Validar autenticação
    if not crypto.user_id:
        return jsonify({"error": "Not authenticated"}), 401
    
    # Validar dados básicos
    if not data.get('auction_id') or not data.get('value'):
        return jsonify({"error": "Missing required fields"}), 400
    
    auction_id = data['auction_id']
    bid_value = float(data['value'])
    
    # Verificar se leilão existe
    auction = db.get_auction(auction_id)
    if not auction:
        return jsonify({"error": "Auction not found"}), 404
    
    # Verificar se leilão ainda está ativo
    closing_date = datetime.fromisoformat(auction.closing_date)
    if datetime.utcnow() > closing_date:
        return jsonify({"error": "Auction is closed"}), 400
    
    # Verificar que bid >= min_bid
    if auction.min_bid and bid_value < auction.min_bid:
        return jsonify({"error": f"Bid deve ser >= {auction.min_bid}€"}), 400

    # Verificar que bid > bids anteriores
    highest_bid = db.get_highest_bid(auction_id)
    if highest_bid and bid_value <= highest_bid.value:
        return jsonify({"error": f"Bid deve ser > {highest_bid.value}€"}), 400

    # Verificar que não é o próprio leilão
    if db.is_my_auction(auction_id):
        return jsonify({"error": "Não pode dar bid no próprio leilão!"}), 400
    
    try:
        # 1. OBTER CHAVE BLIND (CORREÇÃO DO ERRO)
        if not get_or_update_blind_key():
             return jsonify({"error": "Could not obtain server blind key"}), 500

        print("Requesting anonymous token for bid from server...")

        # 2. Gerar mensagem única para o token
        token_message = f"bid_token_{uuid.uuid4()}"
        
        # 3. Cegar a mensagem usando server_blind_pub_key
        blinded_msg, r, m_hash = bs.blind(token_message, server_blind_pub_key)

        # 4. Pedir assinatura cega ao servidor
        token_response = server.get_blind_token(str(blinded_msg))
        
        if not token_response or token_response.get('status') != 'success':
            return jsonify({"error": "Failed to get anonymous token"}), 500
        
        # 5. Remover cegueira (Unblind) usando a chave correta
        blind_sig = int(token_response['blind_signature'])
        signature = bs.unblind(blind_sig, r, server_blind_pub_key)

        # 6. Criar token no formato "hash:signature"
        anonymous_token = bs.signature_to_token(m_hash, signature)  

        print(f"Bid token criado: {anonymous_token[:50]}...")
        
        # 7. PEDIR TIMESTAMP CONFIÁVEL AO SERVIDOR
        # O timestamp garante a ordem dos lances em caso de empate
        bid_data = f"{auction_id}|{bid_value}|{token_message}"
        timestamp_response = server.request_timestamp(bid_data)
        
        if not timestamp_response:
            return jsonify({"error": "Failed to get timestamp"}), 500
        
        timestamp = timestamp_response.get('timestamp')
        timestamp_signature = timestamp_response.get('signature')
        
        print(f"Timestamp obtained: {timestamp}")
        
        # 8. Criar objeto Bid
        bid = Bid(
            auction_id=auction_id,
            value=bid_value
        )
        
        # 9. Preencher dados de segurança e anonimato
        bid.anonymous_token = anonymous_token
        bid.bidder_anonymous_id = crypto.get_anonymous_id()
        bid.timestamp = timestamp
        bid.timestamp_signature = timestamp_signature
        
        # 10. Guardar localmente (is_mine=True)
        db.save_bid(bid, is_mine=True)
        
        # 11. Broadcast para a rede P2P
        network.broadcast_bid(bid)
        
        print(f"Bid broadcasted anonymously: €{bid.value} at {timestamp}")
        
        return jsonify(bid.to_dict()), 201
        
    except Exception as e:
        print(f"Erro ao fazer bid: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/api/bids/mine', methods=['GET'])
def get_my_bids():
    #Retorna bids que EU(utilizador) fiz
    bids = db.get_my_bids()
    return jsonify([bid.to_dict() for bid in bids])


# --- PEERS ---

@app.route('/api/peers', methods=['GET'])
def get_peers():
    #Retorna lista de peers conectados
    peers = network.get_peers()
    return jsonify([{"host": host, "port": port} for host, port in peers])


@app.route('/api/peers', methods=['POST'])
def add_peer():
    #Adiciona novo peer E pede sincronização
    data = request.json
    
    if not data.get('host') or not data.get('port'):
        return jsonify({"error": "Missing host or port"}), 400
    
    peer_host = data['host']
    peer_port = int(data['port'])
    
    # Adicionar peer
    network.add_peer(peer_host, peer_port)
    
    # Pedir sincronização
    try:
        network.request_sync_from_peer(peer_host, peer_port)
        print(f"Solicitada sincronização de {peer_host}:{peer_port}")
    except Exception as e:
        print(f"Erro ao pedir sincronização: {e}")
    
    return jsonify({"message": "Peer added and sync requested"}), 201


@app.route('/api/peers/discover', methods=['POST'])
def discover_peers():
    """Descobre peers registados no servidor central"""
    try:
        users = server.get_users_list()
        
        if not users:
            return jsonify({"message": "No users found", "added": 0}), 200
        
        added = 0
        for user in users:
            # Não adicionar a si próprio
            if user.get('username') != crypto.username:
                network.add_peer(user['ip'], user['port'])
                added += 1
        
        return jsonify({
            "message": f"Discovered {len(users)} users, added {added} peers",
            "peers": users
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/peers/<peer_id>/sync', methods=['POST'])
def sync_with_peer(peer_id):
    #Pede sincronização a um peer específico
    try:
        # peer_id seria algo como "localhost:50234"
        host, port = peer_id.split(':')
        network.request_sync_from_peer(host, int(port))
        return jsonify({"message": "Sync request sent"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- INFO ---

@app.route('/api/info', methods=['GET'])
def get_info():
    #Retorna informações do cliente
    return jsonify({
        "port": network.port,
        "peers_count": len(network.peers),
        "auctions_count": len(db.get_all_auctions()),
        "my_auctions_count": len(db.get_my_auctions())
    })


# ==================== AUTENTICAÇÃO ====================


@app.route('/api/auth/login', methods=['POST'])
def login_user():
    #Faz login e descobre peers automaticamente
    data = request.json
    
    username = data.get('username')
    password = data.get('password')
    
    print(f"\nLogin attempt: username='{username}'")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Login via crypto_manager
    success, message = crypto.login(username, password)
    
    print(f"Login result: success={success}, message='{message}'")
    
    if success:
        global my_user_id
        my_user_id = crypto.user_id
        
        print(f"User ID: {my_user_id}")
        print(f"Username: {crypto.username}")
        
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ip = s.getsockname()[0]
            s.close()
        except:
            my_ip = '127.0.0.1'
        
        server.update_user_address(crypto.user_id, my_ip, network.port)
        print(f"Address updated: {my_ip}:{network.port}")
        
        # Descoberta automática de peers
        try:
            print("\nDiscovering peers from server...")
            users = server.get_users_list()
            
            if users:
                discovered = 0
                for user in users:
                    if user.get('username') != username and user.get('user_id') != my_user_id:
                        network.add_peer(user['ip'], user['port'])
                        discovered += 1
                        print(f"Added peer: {user['username']} ({user['ip']}:{user['port']})")
                
                print(f"Discovered {discovered} peers\n")
                
                # Sincronização automática
                if discovered > 0:
                    print("Requesting sync from all peers...")
                    for peer_host, peer_port in network.get_peers():
                        try:
                            network.request_sync_from_peer(peer_host, peer_port)
                            print(f"Sync requested from {peer_host}:{peer_port}")
                        except Exception as e:
                            print(f"Sync failed: {e}")
            else:
                print("No other peers found on server\n")
        
        except Exception as e:
            print(f"Auto-discovery failed: {e}\n")
        
        return jsonify({
            "message": "Login successful",
            "user_id": crypto.user_id,
            "username": crypto.username
        }), 200
    else:
        print(f"Login failed: {message}\n")
        return jsonify({"error": message}), 401

@app.route('/api/auth/register', methods=['POST'])
def register_user_endpoint():
    # Regista utilizador usando o CryptoManager (que guarda as chaves!)
    data = request.json
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    try:
        # Tenta descobrir o IP (igual ao que tinhas)
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ip = s.getsockname()[0]
            s.close()
        except:
            my_ip = '127.0.0.1'
        
        print(f"Registering with IP: {my_ip}, Port: {network.port}")
        
        # --- A CORREÇÃO ESTÁ AQUI ---
        # Em vez de gerar chaves aqui manualmente, chamamos o manager
        success, message = crypto.register(
            username=username,
            password=password,
            ip=my_ip,
            port=network.port
        )
        # ---------------------------
        
        if success:
            global my_user_id
            my_user_id = crypto.user_id
            
            print(f"\nUser '{username}' registered successfully (ID: {my_user_id})")
            
            # (O resto da lógica de descoberta de peers mantém-se igual...)
            # Copia apenas a parte da Descoberta de Peers do teu código antigo para aqui se quiseres
            # Mas o essencial para as chaves é o bloco acima.

            return jsonify({
                "message": "User registered successfully. Please login.",
                "user_id": crypto.user_id,
                "username": username
            }), 201
        else:
            return jsonify({"error": message}), 400
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    #Verifica se utilizador está autenticado
    if crypto.user_id:
        # Re-descobrir peers se pedido explicitamente
        should_discover = request.args.get('discover') == 'true'
        
        if should_discover:
            try:
                print(f"\nRe-discovering peers for '{crypto.username}'...")
                users = server.get_users_list()
                discovered = 0
                
                for user in users:
                    if user.get('user_id') != crypto.user_id:
                        peer = (user['ip'], user['port'])
                        # Só adicionar se ainda não estiver na lista
                        if peer not in network.get_peers():
                            network.add_peer(user['ip'], user['port'])
                            discovered += 1
                            print(f"New peer: {user['username']} ({user['ip']}:{user['port']})")
                
                if discovered > 0:
                    print(f"Re-discovered {discovered} new peers\n")
                    
                    # Sincronizar com novos peers
                    for peer_host, peer_port in network.get_peers():
                        try:
                            network.request_sync_from_peer(peer_host, peer_port)
                        except:
                            pass
                else:
                    print("No new peers found\n")
            
            except Exception as e:
                print(f"Re-discovery failed: {e}\n")
        
        return jsonify({
            "authenticated": True,
            "user_id": crypto.user_id,
            "username": crypto.username
        }), 200
    else:
        return jsonify({
            "authenticated": False
        }), 200


# ==================== LÓGICA DE REVELAÇÃO DO VENCEDOR ====================

@app.route('/api/auctions/<auction_id>/claim', methods=['POST'])
def claim_auction_win(auction_id):
    #ENDPOINT DO VENDEDOR
    data = request.json
    winner_cert_pem = data.get('certificate')
    winner_token = data.get('winning_token')
    
    # Validações
    if not db.is_my_auction(auction_id):
        return jsonify({"error": "Unauthorized"}), 403
    winning_bid = db.get_winning_bid(auction_id)
    if not winning_bid or winning_bid.anonymous_token != winner_token:
        return jsonify({"error": "Invalid token"}), 400
        
    # Extrair e Guardar Nome
    winner_name = crypto.extract_name_from_cert(winner_cert_pem)
    print(f"\n!!! VENCEDOR REVELADO: {winner_name} !!!")
    db.set_revealed_identity(auction_id, winner_name=winner_name)
    
    return jsonify({
        "status": "confirmed",
        "seller_certificate": crypto.get_certificate()
    }), 200

def on_closed_received(data):
    #CALLBACK DO VENCEDOR
    auction_id = data.get('auction_id')
    winning_token = data.get('winning_token')
    seller_contact = data.get('seller_contact')
    
    # Verificar se ganhei
    my_bids = db.get_my_bids()
    i_won = False
    for bid in my_bids:
        if bid.auction_id == auction_id and bid.anonymous_token == winning_token:
            i_won = True
            break
            
    if i_won:
        print(f"\nGanhaste o leilão! Contactando vendedor em {seller_contact}...")
        try:
            payload = {
                "winning_token": winning_token,
                "certificate": crypto.get_certificate()
            }
            url = f"http://{seller_contact}/api/auctions/{auction_id}/claim"
            res = requests.post(url, json=payload, timeout=5)
            
            if res.status_code == 200:
                seller_cert = res.json().get('seller_certificate')
                seller_name = crypto.extract_name_from_cert(seller_cert)
                print(f" Vendedor Revelado: {seller_name}")
                
                # Guardar na BD
                db.set_revealed_identity(auction_id, seller_name=seller_name)
            else:
                print(f"Erro no handshake: {res.text}")
        except Exception as e:
            print(f"Falha ao contactar vendedor: {e}")


# ==================== STARTUP ====================

def check_auctions_thread():
    #THREAD DO VENDEDOR: Verifica periodicamente se os meus leilões acabaram.
    #Se acabaram, calcula o vencedor e avisa a rede.
    processed = set()
    discovery_timer = 0
    
    while True:
        time.sleep(5) # Verifica a cada 5 segundos
        discovery_timer += 1
        if discovery_timer >= 6:
            try:
                # Pergunta ao servidor quem está online
                users = server.get_users_list()
                for user in users:
                    # Se não sou eu, adiciona
                    if user.get('user_id') != crypto.user_id:
                         network.add_peer(user['ip'], user['port'])
                discovery_timer = 0
            except:
                pass
        try:
            # Se a DB ainda não estiver pronta ou fechada
            if not db: continue

            my_auctions = db.get_my_auctions()
            now = datetime.utcnow()
            
            for auction in my_auctions:
                # Se já fechou e ainda não processámos
                close_date = datetime.fromisoformat(auction.closing_date)
                
                if now > close_date and auction.auction_id not in processed:
                    
                    winning_bid = db.get_winning_bid(auction.auction_id)
                    
                    if winning_bid:
                        print(f"\n[AUTO] Encerrando leilão '{auction.item}'. Anunciando vencedor...")
                        
                        # Descobrir o meu IP para o vencedor me contactar
                        import socket
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            s.connect(("8.8.8.8", 80))
                            my_ip = s.getsockname()[0]
                            s.close()
                        except:
                            my_ip = '127.0.0.1'
                            
                        # O vencedor deve contactar a minha API REST (não a porta P2P)
                        contact_info = f"{my_ip}:5001"
                        
                        network.broadcast_auction_closed(
                            auction.auction_id,
                            winning_bid.anonymous_token,
                            contact_info
                        )
                    else:
                        print(f"\n[AUTO] Leilão '{auction.item}' fechou sem licitações.")
                    
                    processed.add(auction.auction_id)
                    
        except Exception as e:
            # Ignorar erros de DB locked temporários
            pass

def start_client():
    #Inicia todos os componentes
    print("=" * 60)
    print("AUCTION CLIENT")
    print("=" * 60)
    
    # Obter certificado da CA ao iniciar
    try:
        ca_cert = server.get_ca_certificate()
        if ca_cert:
            print("CA Certificate obtained from server")
        else:
            print("Could not get CA certificate")
    except Exception as e:
        print(f"Error getting CA certificate: {e}")
    
    print(f"\nAPI Server: http://localhost:5001")
    print(f"P2P Port: {network.port} (will start after Flask)")
    print(f"\nEndpoints:")
    print("  POST /api/auth/register - Register user")
    print("  POST /api/peers/discover - Discover peers from server")
    print("  POST /api/peers - Add peer manually")
    print("="*60 + "\n")
    
    # Iniciar API REST (Flask)
    app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False)


# ==================== P2P DELAYED START ====================

def init_p2p():
    #Inicia P2P após Flask estar pronto
    time.sleep(0.5)  # Espera Flask iniciar
    network.start()
    print(f"\nP2P Network started on port {network.port}\n")




def cleanup():
    #Cleanup resources before shutting down
    print('\nShutting down gracefully...')
    
    # Fecha a base de dados
    if 'db' in globals() and db:
        try:
            db.close()
            print('Database closed')
        except Exception as e:
            print(f'Error closing database: {e}')
    
    # Para o P2P network (corrigido de p2p_node para network)
    if 'network' in globals() and network:
        try:
            network.stop()
            print('P2P network stopped')
        except Exception as e:
            print(f'Error stopping P2P network: {e}')
    
    print('Goodbye!')

def signal_handler(sig, frame):
    #Handle CTRL+C and other termination signals
    cleanup()
    sys.exit(0)

# ==================== MAIN ====================

if __name__ == '__main__':
    # Regista cleanup para shutdown graceful
    signal.signal(signal.SIGINT, signal_handler)   # CTRL+C
    signal.signal(signal.SIGTERM, signal_handler)  
    
    # Registo de todos os callbacks 
    network.register_callbacks(
        on_auction=on_auction_received,
        on_bid=on_bid_received,
        on_sync_received=on_sync_received,
        on_auction_closed=on_closed_received  
    )
    
    # Iniciar a thread do vendedor (para fechar leilões automaticamente) 
    # Daemon=True significa que a thread morre quando o programa principal fechar
    closer_thread = threading.Thread(target=check_auctions_thread, daemon=True)
    closer_thread.start()
    
    # Registra P2P para iniciar depois (mantém-se igual)
    threading.Timer(1.0, init_p2p).start()
    
    try:
        start_client()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        cleanup()