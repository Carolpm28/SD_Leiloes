"""
Estruturas de dados do sistema de leilões
Define os formatos de auctions, bids e messages
"""

from datetime import datetime
from typing import Optional
import uuid


class Auction:
    """
    Representa um anúncio de leilão
    """
    
    def __init__(self, item: str, closing_date: str, min_bid: Optional[float] = None, categoria: Optional[str] = None):
        # ← categoria TEM QUE ESTAR AQUI!
        self.auction_id = str(uuid.uuid4())
        self.item = item
        self.closing_date = closing_date
        self.min_bid = min_bid
        self.categoria = categoria  # ← AGORA pode usar
        self.signature = None
        self.seller_anonymous_id = None
        
    def to_dict(self):
        """Converte para dicionário (para enviar pela rede)"""
        return {
            "auction_id": self.auction_id,
            "item": self.item,
            "closing_date": self.closing_date,
            "min_bid": self.min_bid,
            "categoria": self.categoria,
            "signature": self.signature,
            "seller_anonymous_id": self.seller_anonymous_id
        }
    
    @staticmethod
    def from_dict(data: dict):
        """Cria Auction a partir de dicionário"""
        auction = Auction(
            item=data["item"],
            closing_date=data["closing_date"],
            min_bid=data.get("min_bid"),
            categoria=data.get("categoria")
        )
        auction.auction_id = data["auction_id"]
        auction.signature = data.get("signature")
        auction.seller_anonymous_id = data.get("seller_anonymous_id")
        return auction


class Bid:
    """
    Representa uma proposta (bid)
    BID NÃO TEM CATEGORIA!
    """
    
    def __init__(self, auction_id: str, value: float):
        self.bid_id = str(uuid.uuid4())
        self.auction_id = auction_id
        self.value = value
        self.timestamp = datetime.utcnow().isoformat()
        self.signature = None
        self.bidder_cert = None
        self.bidder_anonymous_id = None
        # ← SEM categoria!
        
    def to_dict(self):
        return {
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "value": self.value,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "bidder_cert": self.bidder_cert,
            "bidder_anonymous_id": self.bidder_anonymous_id
        }
    
    @staticmethod
    def from_dict(data: dict):
        bid = Bid(
            auction_id=data["auction_id"],
            value=data["value"]
            # ← SEM categoria!
        )
        bid.bid_id = data["bid_id"]
        bid.timestamp = data["timestamp"]
        bid.signature = data.get("signature")
        bid.bidder_cert = data.get("bidder_cert")
        bid.bidder_anonymous_id = data.get("bidder_anonymous_id")
        return bid


class P2PMessage:
    """
    Mensagem genérica para comunicação P2P
    """
    
    def __init__(self, msg_type: str, data: dict):
        self.type = msg_type
        self.data = data
        self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self):
        return {
            "type": self.type,
            "data": self.data,
            "timestamp": self.timestamp
        }