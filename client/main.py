#Aplicação principal do cliente de leilões. Coordena: Database, P2P Network, Crypto e API REST
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime
import threading  
import time
import atexit

from database import Database
from p2p_network import P2PNetwork
from models import Auction, Bid
from crypto_manager import CryptoManager
from server_client import ServerClient  

# ==================== INICIALIZAÇÃO ====================

app = Flask(__name__)
CORS(app)  # Permite requests da frontend

# Componentes
db = Database("auction_client.db")
network = P2PNetwork(port=0, database=db)
crypto = CryptoManager(server_url="http://localhost:5000")
server = ServerClient()  

# Estado global
my_user_id = None  # ID do utilizador (definir depois)

print("Starting Auction Client...")


# ==================== CALLBACKS P2P ====================

def on_auction_received(auction: Auction):
    #Callback quando recebe novo leilão via P2P
    print(f"Received auction: {auction.item}")
    
    # Guardar na base de dados (is_mine=False porque veio da rede)
    db.save_auction(auction, is_mine=False)
    
    # TODO: Verificar assinatura com crypto


def on_bid_received(bid: Bid):
    #Callback quando recebe novo bid via P2P
    print(f"Received bid: €{bid.value:.2f} for auction {bid.auction_id}")
    
    # Guardar na base de dados
    db.save_bid(bid, is_mine=False)
    
    # TODO: Verificar assinatura com crypto


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

# Registar callbacks
network.register_callbacks(
    on_auction=on_auction_received,
    on_bid=on_bid_received,
    on_sync_received=on_sync_received  
)


# ==================== API REST ====================

# --- SERVIR FRONTEND ---

@app.route('/')
def index():
    """Serve a página principal (index.html)"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    ui_dir = os.path.join(current_dir, 'ui')
    return send_from_directory(ui_dir, 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    """Serve CSS, JS e outros ficheiros estáticos"""
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
    """Cria novo leilão com anonimato"""
    
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
        
        # Gerar mensagem para blind signature
        import secrets
        import hashlib
        
        message = f"AUCTION_{secrets.token_hex(16)}"
        msg_hash = hashlib.sha256(message.encode()).hexdigest()
        
        # Pedir token cego ao servidor
        token_response = server.get_blind_token(msg_hash)
        
        if token_response:
            anonymous_token = token_response.get('blind_signature', msg_hash[:32])
            print(f"Anonymous token obtained: {anonymous_token[:20]}...")
        else:
            anonymous_token = msg_hash[:32]
            print(f"Using fallback token: {anonymous_token[:20]}...")
        
        # ← CORRIGIDO: Criar leilão só com parâmetros aceites
        auction = Auction(
            item=item,
            closing_date=closing_date,
            min_bid=float(min_bid) if min_bid else None,
            categoria=categoria
        )
        
        # ← Definir atributos adicionais DEPOIS
        auction.anonymous_token = anonymous_token
        auction.seller_anonymous_id = crypto.get_anonymous_id()
        
        # Guardar na base de dados local
        db.save_auction(auction, is_mine=True)
        
        # Broadcast P2P
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
    #Cria novo bid ANÓNIMO com blind signature
    data = request.json
    
    # Validar autenticação
    if not crypto.user_id:
        return jsonify({"error": "Not authenticated"}), 401
    
    # Validar dados
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
        # 1. PEDIR TOKEN ANÓNIMO AO SERVIDOR CENTRAL
        print("Requesting anonymous token for bid from server...")
        
        import uuid
        token_message = f"bid_token_{uuid.uuid4()}"
        
        # ← ALTERAR: Usar server_client
        token_response = server.get_blind_token(token_message)
        
        if not token_response:
            return jsonify({"error": "Failed to get anonymous token"}), 500
        
        token = token_response.get('blind_signature')
        print(f"Anonymous token obtained: {token[:40]}...")
        
        # 2. PEDIR TIMESTAMP CONFIÁVEL AO SERVIDOR
        bid_data = f"{auction_id}|{bid_value}|{token_message}"
        timestamp_response = server.request_timestamp(bid_data)
        
        if not timestamp_response:
            return jsonify({"error": "Failed to get timestamp"}), 500
        
        timestamp = timestamp_response.get('timestamp')
        timestamp_signature = timestamp_response.get('signature')
        
        print(f"Timestamp obtained: {timestamp}")
        
        # 3. Criar bid
        bid = Bid(
            auction_id=auction_id,
            value=bid_value
        )
        
        # 4. ADICIONAR TOKEN ANÓNIMO E TIMESTAMP
        bid.anonymous_token = token
        bid.bidder_anonymous_id = crypto.get_anonymous_id()
        bid.timestamp = timestamp
        bid.timestamp_signature = timestamp_signature
        
        # 5. Guardar localmente (is_mine=True)
        db.save_bid(bid, is_mine=True)
        
        # 6. Broadcast para a rede P2P
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


# ← NOVO ENDPOINT: Descobrir peers via servidor central
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
    """Faz login e descobre peers automaticamente"""
    data = request.json
    
    username = data.get('username')
    password = data.get('password')
    
    print(f"\n🔐 Login attempt: username='{username}'")  # ← DEBUG
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Login via crypto_manager
    success, message = crypto.login(username, password)
    
    print(f"   Login result: success={success}, message='{message}'")  # ← DEBUG
    
    if success:
        global my_user_id
        my_user_id = crypto.user_id
        
        print(f"   User ID: {my_user_id}")  # ← DEBUG
        print(f"   Username: {crypto.username}")  # ← DEBUG
        
        # Descoberta automática de peers
        try:
            print("\n🔍 Discovering peers from server...")
            users = server.get_users_list()
            
            if users:
                discovered = 0
                for user in users:
                    if user.get('username') != username and user.get('user_id') != my_user_id:
                        network.add_peer(user['ip'], user['port'])
                        discovered += 1
                        print(f"  → Added peer: {user['username']} ({user['ip']}:{user['port']})")
                
                print(f"✓ Discovered {discovered} peers\n")
                
                # Sincronização automática
                if discovered > 0:
                    print("Requesting sync from all peers...")
                    for peer_host, peer_port in network.get_peers():
                        try:
                            network.request_sync_from_peer(peer_host, peer_port)
                            print(f"  → Sync requested from {peer_host}:{peer_port}")
                        except Exception as e:
                            print(f"  ✗ Sync failed: {e}")
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
        print(f"   ✗ Login failed: {message}\n")  # ← DEBUG
        return jsonify({"error": message}), 401


@app.route('/api/auth/register', methods=['POST'])
def register_user_endpoint():
    """Regista utilizador no servidor central"""
    data = request.json
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    try:
        # Gerar chave pública
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Registar no servidor
        response = server.register_user(
            username=username,
            public_key=public_key_pem,
            ip='localhost',
            port=network.port
        )
        
        if response.get('status') == 'success':
            # Guardar info localmente
            global my_user_id
            my_user_id = response['user_id']
            crypto.user_id = response['user_id']
            crypto.username = username
            
            # ← ADICIONAR ISTO APENAS se a tua interface fizer login automático após registo
            # Se precisar de fazer login manual depois, NÃO adicionar isto aqui
            # (deixa só no endpoint de login)
            
            # SE fizer login automático:
            try:
                print(f"\n🔍 Discovering peers for new user '{username}'...")
                users = server.get_users_list()
                
                if users:
                    discovered = 0
                    for user in users:
                        if user.get('user_id') != my_user_id:
                            network.add_peer(user['ip'], user['port'])
                            discovered += 1
                            print(f"  → Added peer: {user['username']} ({user['ip']}:{user['port']})")
                    
                    print(f"✓ Discovered {discovered} peers\n")
                    
                    # Sincronização inicial
                    if discovered > 0:
                        for peer_host, peer_port in network.get_peers():
                            try:
                                network.request_sync_from_peer(peer_host, peer_port)
                            except:
                                pass
            
            except Exception as e:
                print(f"⚠️  Auto-discovery after registration failed: {e}")
            
            return jsonify({
                "message": "User registered successfully",
                "user_id": response['user_id'],
                "username": username
            }), 201
        else:
            return jsonify({"error": response.get('message', 'Registration failed')}), 400
    
    except Exception as e:
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
                            print(f"  → New peer: {user['username']} ({user['ip']}:{user['port']})")
                
                if discovered > 0:
                    print(f"✓ Re-discovered {discovered} new peers\n")
                    
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

# ==================== STARTUP ====================

def start_client():
    #Inicia todos os componentes
    print("=" * 60)
    print("AUCTION CLIENT")
    print("=" * 60)
    
    # Obter certificado da CA ao iniciar
    try:
        ca_cert = server.get_ca_certificate()
        if ca_cert:
            print("✓ CA Certificate obtained from server")
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
    print(f"\n✓ P2P Network started on port {network.port}\n")

# Cleanup ao sair
atexit.register(lambda: network.stop())
atexit.register(lambda: db.close())


# ==================== MAIN ====================

if __name__ == '__main__':
    # Registra P2P para iniciar depois
    threading.Timer(1.0, init_p2p).start()
    
    try:
        start_client()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        print("Goodbye!")