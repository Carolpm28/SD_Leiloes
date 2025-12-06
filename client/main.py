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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
        
        try:
            expected_data = f"{bid.auction_id}|{bid.value}|{bid.anonymous_token}"
            ca_cert_obj = crypto.get_ca_certificate()
            server_pub_key_pem = ca_cert_obj.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            data_to_verify = f"{expected_data}|{bid.timestamp}"
        
            is_integrity_valid = crypto.verify_signature(
                data_to_verify, 
                bid.timestamp_signature, # Assinatura que veio na Bid
                server_pub_key_pem       # Chave Pública do Servidor
            )

            if not is_integrity_valid:
                print("ALERTA: Falha na integridade da Bid! Valor ou Timestamp adulterados.")
                return # Rejeitar bid corrupta

            print("✓ Integridade da Bid verificada (Timestamp válido)")

        except Exception as e:
            print(f"Erro a verificar integridade: {e}")
            return
    
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

def on_reveal_received(reveal_data):
    auction_id = reveal_data.get('auction_id')
    winner_name = reveal_data.get('winner_name')
    seller_name = reveal_data.get('seller_name')
    
    # 1. Atualizar o registo do leilão local
    db.set_revealed_identity(auction_id, winner_name=winner_name, seller_name=seller_name)
    
    # 2. Verificar se o leilão era um dos meus bids vencedores (para notificar o frontend)
    my_winning_bid = db.get_winning_bid(auction_id)
    if my_winning_bid and my_winning_bid.is_mine:
         print(f"\n------O Vendedor do leilão {auction_id[:8]}... foi revelado: {seller_name}")
    else:
         print(f"\n------Revelação recebida. Vendedor: {seller_name}, Vencedor: {winner_name}")

def on_identity_reveal_received(data):
    #Callback chamado quando a identidade do vendedor é revelada via P2P
    winner_anon_id = data.get('winner_anonymous_id')
    
    # 1. Verifica: Sou eu o Vencedor deste bid?
    if winner_anon_id == crypto.get_anonymous_id():
        seller_name = data.get('seller_username')
        auction_id = data.get('auction_id')
        
        print(f"\nRecebida Identidade do Vendedor: {seller_name}")
        
        # 2. Guardar a identidade do Vendedor na minha base de dados
        # A função set_revealed_identity usa seller_name=seller_name
        db.set_revealed_identity(auction_id, seller_name=seller_name)
        
        print(f"Nome do Vendedor ({seller_name}) guardado para leilão {auction_id[:8]}.")
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
    # Cria novo leilão com Anonimato, Chaves Efémeras e Registo de Propriedade
    
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
        print("\n[Auction] Starting creation process...")
        
        # 1. Garantir que temos a chave pública correta do servidor
        if not get_or_update_blind_key():
             return jsonify({"error": "Could not obtain server blind key"}), 500

        # 2. Gerar mensagem para o token
        message = f"AUCTION_{secrets.token_hex(16)}"
        
        # 3. Blind Signature Flow
        print("[Auction] Requesting anonymous token...")
        blinded_msg, r, m_hash = bs.blind(message, server_blind_pub_key)
        
        token_response = server.get_blind_token(str(blinded_msg)) 

        if token_response and token_response.get('status') == 'success':
            blind_sig = int(token_response['blind_signature'])
            signature = bs.unblind(blind_sig, r, server_blind_pub_key)
            anonymous_token = bs.signature_to_token(m_hash, signature) 
            print(f"[Auction] Token obtido: {anonymous_token[:20]}...")
        else:
            raise Exception("Server refused to sign blind token")
        
        # 4. Criar objeto Auction (inicial)
        auction = Auction(
            item=item,
            closing_date=closing_date,
            min_bid=float(min_bid) if min_bid else None,
            categoria=categoria
        )

        # 5. Gerar Chaves Efémeras (O "Cofre" do Leilão)
        print("[Auction] Generating ephemeral keys...")
        ephemeral_priv, ephemeral_pub = crypto.generate_ephemeral_keys()
        
        # 6. Guardar a Chave Privada LOCALMENTE (Fundamental para revelar vencedor depois)
        keys_path = os.path.join("keys", "auctions")
        os.makedirs(keys_path, exist_ok=True)
        
        priv_key_file = os.path.join(keys_path, f"{auction.auction_id}.key")
        with open(priv_key_file, "w") as f:
            f.write(ephemeral_priv)
            
        # 7. Configurar dados de segurança no objeto Auction
        auction.ephemeral_public_key = ephemeral_pub
        auction.anonymous_token = anonymous_token
        auction.seller_anonymous_id = crypto.get_anonymous_id()
        
        # 8. REGISTAR NO NOTÁRIO (Prova de Propriedade)
        # Dizemos ao servidor: "Este leilão é meu, validado por esta chave pública"
        print("[Auction] Registering ownership with Notary...")
        reg_response = server.register_auction(
            auction.auction_id,
            ephemeral_pub,      # A chave que prova quem manda
            anonymous_token
        )
        
        if reg_response.get('status') != 'success':
            # Se falhar o registo, abortar (senão nunca conseguirás revelar o vencedor)
            os.remove(priv_key_file) # Limpar chave orfã
            return jsonify({"error": f"Notary registration failed: {reg_response.get('message')}"}), 500
        
        print("[Auction] Ownership registered successfully.")

        # 9. Guardar na base de dados local
        db.save_auction(auction, is_mine=True)
        
        # 10. Broadcast P2P
        network.broadcast_auction(auction)
        
        print(f"[Auction] Broadcasted anonymously: {item}")
        
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
    #highest_bid = db.get_highest_bid(auction_id)
    #if highest_bid and bid_value <= highest_bid.value:
        #return jsonify({"error": f"Bid deve ser > {highest_bid.value}€"}), 400

    # Verificar que não é o próprio leilão
    if db.is_my_auction(auction_id):
        return jsonify({"error": "Não pode dar bid no próprio leilão!"}), 400
    
    try:
        # Se a chave Notário/Blind falhar, o processo para aqui.
        if not get_or_update_blind_key():
             return jsonify({"error": "Could not obtain server blind key"}), 500

        print("Requesting anonymous token for bid from server...")
        token_message = f"bid_token_{uuid.uuid4()}"
        
        # 2. Cegar, pedir assinatura e Descegar (Resultado em anonymous_token)
        blinded_msg, r, m_hash = bs.blind(token_message, server_blind_pub_key)
        token_response = server.get_blind_token(str(blinded_msg))
        
        if not token_response or token_response.get('status') != 'success':
            return jsonify({"error": "Failed to get anonymous token"}), 500
        
        blind_sig = int(token_response['blind_signature'])
        signature = bs.unblind(blind_sig, r, server_blind_pub_key)
        anonymous_token = bs.signature_to_token(m_hash, signature)
        
        # --- PASSO 2: CIFRAR IDENTIDADE PARA O SERVIDOR NOTÁRIO ---
        encrypted_identity_blob = crypto.encrypt_identity_for_notary(auction_id, bid_value)

        print("Storing identity blob with Notary...")
        store_response = server.store_identity_blob(
            auction_id, 
            anonymous_token, 
            encrypted_identity_blob
        )
        if store_response.get('status') != 'success':
            # Se o Notário falhar, o bid não deve ser feito.
            raise Exception(f"Failed to store identity blob with Notary: {store_response.get('message', 'Unknown error')}")
        print("Identity blob successfully stored by Notary.")
        
        # --- PASSO 3: OBTER TIMESTAMP ---
        bid_data = f"{auction_id}|{bid_value}|{anonymous_token}"
        timestamp_response = server.request_timestamp(bid_data)
        
        if not timestamp_response:
            return jsonify({"error": "Failed to get timestamp"}), 500
        
        timestamp = timestamp_response.get('timestamp')
        timestamp_signature = timestamp_response.get('signature')
       
        # --- PASSO 4: CRIAR E ENVIAR O BID FINAL ---
        bid = Bid(
            auction_id=auction_id,
            value=bid_value
        )
        
        bid.anonymous_token = anonymous_token
        bid.bidder_anonymous_id = crypto.get_anonymous_id()
        bid.timestamp = timestamp
        bid.timestamp_signature = timestamp_signature
        bid.encrypted_identity_blob = encrypted_identity_blob # O ENVELOPE SELADO
        
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
    # Callback quando recebe notificação de fecho de leilão
    auction_id = data.get('auction_id')
    winning_token = data.get('winning_token')
    
    print(f"\nAVISO: Leilão {auction_id[:8]}... fechou. Verificando token...")
    
    # Verificar se EU sou o vencedor (a única coisa que interessa)
    my_bids = db.get_my_bids()
    i_won = False
    for bid in my_bids:
        # Nota: O Vendedor devia enviar o token do vencedor (que o Comprador confere com os seus bids)
        if bid.auction_id == auction_id and bid.anonymous_token == winning_token:
            i_won = True
            break
            
    if i_won:
        print("\nParabens! Ganhaste o leilão!")
        print("A tua identidade está segura com o Servidor Notário.")
        print("Faz Refresh na página para ver a identidade do Vendedor.")
        # A identidade do Vendedor será revelada quando o Vendedor contactar o Notário 
        # e o Servidor atualizar os dados na rede.
    else:
        print("Fecho de leilão recebido. Não é o nosso bid.")


# ==================== STARTUP ====================

def check_auctions_thread():
    #THREAD DO VENDEDOR: Verifica periodicamente se os meus leilões acabaram. Se acabaram, calcula o vencedor e pede a revelação da identidade ao Servidor Notário.
 
    processed = set()
    discovery_timer = 0
    
    # A variável API_PORT é usada para garantir que a thread tem acesso ao número da porta
    API_PORT = globals().get('API_PORT', 5001) 
    
    while True:
        time.sleep(5) # Verifica a cada 5 segundos
        
        # Lógica de Descoberta de Peers (Corre a cada 30 segundos)
        discovery_timer += 1
        if discovery_timer >= 6: 
            try:
                users = server.get_users_list()
                for user in users:
                    if user.get('user_id') != crypto.user_id:
                         network.add_peer(user['ip'], user['port'])
                discovery_timer = 0
            except:
                pass

        try:
            # Se a DB ainda não estiver pronta ou o utilizador não autenticado
            if not db or not crypto.user_id: continue

            my_auctions = db.get_my_auctions()
            now = datetime.utcnow()
            
            for auction in my_auctions:
                close_date = datetime.fromisoformat(auction.closing_date)
                
                # 1. Detetar Fecho
                if now > close_date and auction.auction_id not in processed:
                    
                    winning_bid = db.get_winning_bid(auction.auction_id)
                    
                    # 2. Verificar se existe Bid (CORREÇÃO)
                    # NOTA: O winning_bid.encrypted_identity_blob será SEMPRE None para um bid recebido
                    if winning_bid: 
                        print(f"\n[AUTO] Encerrando leilão '{auction.item}'. A pedir revelação ao Notário...")
                        
                        
                        try:
                            # 1. Carregar a Chave Privada Efémera do disco
                            key_path = f"keys/auctions/{auction.auction_id}.key"
                            if not os.path.exists(key_path):
                                print(f"Erro: Chave privada do leilão perdida em {key_path}")
                                # Marcar como processado para não tentar sempre
                                processed.add(auction.auction_id) 
                                continue

                            with open(key_path, "rb") as f:
                                auction_priv_key = serialization.load_pem_private_key(
                                    f.read(), password=None, backend=default_backend()
                                )
                            
                            # 2. Assinar "auction_id|winning_token"
                            payload_to_sign = f"{auction.auction_id}|{winning_bid.anonymous_token}".encode('utf-8')
                            
                            signature = auction_priv_key.sign(
                                payload_to_sign,
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                hashes.SHA256()
                            ).hex()
                            
                        except Exception as e:
                            print(f"Erro ao assinar pedido de revelação: {e}")
                            continue
                        # ------------------------------

                        # 3. Enviar pedido COM assinatura
                        response = server.send_request({
                            'action': 'reveal_identity',
                            'auction_id': auction.auction_id,
                            'winning_token': winning_bid.anonymous_token,
                            'seller_user_id': crypto.user_id,
                            'signature': signature  # <--- ENVIAR A PROVA
                        })
                        
                        # 3. Processar Resposta
                        if response and response.get('status') == 'success':
                            winner_name = response.get('winner_username')
                            # winning_bid (objeto Bid local, obtido no início do loop)
                            print(f"     Identidade revelada pelo notario: {winner_name} ")

                            if winning_bid and winning_bid.bidder_anonymous_id:
                                network.broadcast_identity_reveal(
                                    auction.auction_id,
                                    crypto.username,                    # Nome do Vendedor (você)
                                    winning_bid.bidder_anonymous_id     # ID anónimo do Vencedor (filtro)
                                )
                                print(f"Broadcasted Seller Identity to anonymous ID: {winning_bid.bidder_anonymous_id[:8]}...")
                            else:
                                print("ERRO: Bid vencedor não tem ID anónimo para broadcast P2P.")
                            
                            # (O Vendedor também deve guardar o nome do Vencedor, o que já faz)
                            db.set_revealed_identity(auction.auction_id, winner_name=winner_name)
                            # -------------------------------------------------------------

                        else:
                            print(f"Revelação recusada: {response.get('message', 'Erro desconhecido')} ")
                            
                        # -------------------------------------------------------------
                        
                    else: # Se não há bids (winning_bid é None)
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
        on_auction_closed=on_closed_received,
        on_reveal=on_reveal_received,
        on_identity_reveal=on_identity_reveal_received
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