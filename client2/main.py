"""
Aplicação principal do cliente de leilões
Coordena: Database, P2P Network, Crypto e API REST
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
from datetime import datetime

from database import Database
from p2p_network import P2PNetwork
from models import Auction, Bid

# ==================== INICIALIZAÇÃO ====================

app = Flask(__name__)
CORS(app)  # Permite requests da frontend

# Componentes
db = Database("auction_client.db")
network = P2PNetwork(port=0)

# Estado global
my_user_id = None  # ID do utilizador (definir depois)

print("Starting Auction Client...")


# ==================== CALLBACKS P2P ====================

def on_auction_received(auction: Auction):
    """Callback quando recebe novo leilão via P2P"""
    print(f"Received auction: {auction.item}")
    
    # Guardar na base de dados (is_mine=False porque veio da rede)
    db.save_auction(auction, is_mine=False)
    
    # TODO: Verificar assinatura com crypto


def on_bid_received(bid: Bid):
    #Callback quando recebe novo bid via P2P
    print(f"Received bid: {bid.value}€ for auction {bid.auction_id}")
    
    # Guardar na base de dados
    db.save_bid(bid, is_mine=False)
    
    # TODO: Verificar assinatura com crypto


# Registar callbacks
network.register_callbacks(
    on_auction=on_auction_received,
    on_bid=on_bid_received
)


# ==================== API REST ====================

# --- SERVIR FRONTEND ---

@app.route('/')
def index():
    #Serve a página principal 
    # Frontend está na pasta raiz do projeto
    return send_from_directory('..', 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    #Serve CSS, JS e outros ficheiros estáticos
    return send_from_directory('..', filename)


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
    #Cria novo leilão e faz broadcast
    data = request.json
    
    # Validar dados
    if not data.get('item') or not data.get('closing_date'):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Criar leilão
    auction = Auction(
        item=data['item'],
        closing_date=data['closing_date'],
        min_bid=data.get('min_bid')
    )
    
    # TODO: Assinar com crypto
    
    # Guardar localmente (is_mine=True)
    db.save_auction(auction, is_mine=True)
    
    # Broadcast para a rede P2P
    network.broadcast_auction(auction)
    
    print(f"Created auction: {auction.item}")
    
    return jsonify(auction.to_dict()), 201


@app.route('/api/auctions/<auction_id>', methods=['GET'])
def get_auction(auction_id):
    #Retorna detalhes de um leilão específico
    auction = db.get_auction(auction_id)
    
    if not auction:
        return jsonify({"error": "Auction not found"}), 404
    
    return jsonify(auction.to_dict())


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
    #Cria novo bid e faz broadcast
    data = request.json
    
    # Validar dados
    if not data.get('auction_id') or not data.get('value'):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Verificar se leilão existe
    auction = db.get_auction(data['auction_id'])
    if not auction:
        return jsonify({"error": "Auction not found"}), 404
    
    # Verificar se leilão ainda está ativo
    closing_date = datetime.fromisoformat(auction.closing_date)
    if datetime.utcnow() > closing_date:
        return jsonify({"error": "Auction is closed"}), 400
    
    # Criar bid
    bid = Bid(
        auction_id=data['auction_id'],
        value=float(data['value'])
    )
    
    # TODO: Assinar com crypto
    
    # Guardar localmente (is_mine=True)
    db.save_bid(bid, is_mine=True)
    
    # Broadcast para a rede P2P
    network.broadcast_bid(bid)
    
    print(f"Created bid: {bid.value}€ for {auction.item}")
    
    return jsonify(bid.to_dict()), 201


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
    #Adiciona novo peer
    data = request.json
    
    if not data.get('host') or not data.get('port'):
        return jsonify({"error": "Missing host or port"}), 400
    
    network.add_peer(data['host'], int(data['port']))
    
    return jsonify({"message": "Peer added"}), 201


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


# ==================== STARTUP ====================

def start_client():
    #Inicia todos os componentes
    print("AUCTION CLIENT")
    
    # 1. Iniciar P2P Network
    network.start()
    print(f"P2P Network started on port {network.port}")
    
    # 2. TODO: Registar no servidor central para descobrir peers
    # discovery.register(network.port)
    
    print(f"\nAPI Server: http://localhost:5002")
    print(f"P2P Port: {network.port}")
    print(f"\n Para adicionar peers, usa: POST /api/peers")
    print("="*50 + "\n")
    
    # 3. Iniciar API REST (Flask)
    app.run(host='0.0.0.0', port=5002, debug=False)


if __name__ == '__main__':
    try:
        start_client()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        network.stop()
        db.close()
        print("Goodbye!")