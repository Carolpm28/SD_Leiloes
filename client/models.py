#Estruturas de dados para o sistema
#definem os formatos de auctions, bids e messages

from datetime import datetime
from typing import Optional
import uuid


class Auction:
    #representa o auncio 

    def __init__(self, item: str, closing_date: str, min_bid: Optional[float] = None):
        self.auction_id = str(uuid.uuid4())  # ID único
        self.item = item
        self.closing_date = closing_date
        self.min_bid = min_bid
        self.signature = None  # Será preenchido pelo crypto
        self.seller_anonymous_id = None  # ID anónimo do vendedor
        
    def to_dict(self):
        #Converte para dicionário (para enviar pela rede)
        return {
            "auction_id": self.auction_id,
            "item": self.item,
            "closing_date": self.closing_date,
            "min_bid": self.min_bid,
            "signature": self.signature,
            "seller_anonymous_id": self.seller_anonymous_id
        }
    
    @staticmethod
    def from_dict(data: dict):
        #Cria Auction a partir de dicionário (quando recebe da rede)
        auction = Auction(
            item=data["item"],
            closing_date=data["closing_date"],
            min_bid=data.get("min_bid")
        )
        auction.auction_id = data["auction_id"]
        auction.signature = data.get("signature")
        auction.seller_anonymous_id = data.get("seller_anonymous_id")
        return auction


class Bid:
    #Representa uma proposta (bid)
    
    def __init__(self, auction_id: str, value: float):
        self.bid_id = str(uuid.uuid4())
        self.auction_id = auction_id
        self.value = value
        self.timestamp = datetime.utcnow().isoformat()
        self.signature = None  # Assinatura do bidder
        self.bidder_cert = None  # Certificado X.509 em PEM
        self.bidder_anonymous_id = None  # ID anónimo
        
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
        )
        bid.bid_id = data["bid_id"]
        bid.timestamp = data["timestamp"]
        bid.signature = data.get("signature")
        bid.bidder_cert = data.get("bidder_cert")
        bid.bidder_anonymous_id = data.get("bidder_anonymous_id")
        return bid


class P2PMessage:
    #Encapsula auctions e bids
    
    def __init__(self, msg_type: str, data: dict):
        self.type = msg_type  # "auction", "bid", "winner_reveal"
        self.data = data
        self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self):
        return {
            "type": self.type,
            "data": self.data,
            "timestamp": self.timestamp
        }