#Gestão da base de dados local
#Guarda auctions, bids e utilizadores

import sqlite3
import json
from typing import List, Optional
from models import Auction, Bid
from datetime import datetime


class Database:
    def __init__(self, db_path="auction_client.db"):
        #Inicializa a base de dados, se não existir, cria as tabelas necessárias
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        self.conn.row_factory = sqlite3.Row  # Permite aceder por nome de coluna
        # Ativa WAL mode para melhor concorrência e prevenir corrupção
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA synchronous=NORMAL')
        self._create_tables()
    
    def _create_tables(self):
        #Cria as tabelas se não existirem
        cursor = self.conn.cursor()
        
        # Tabela de leilões
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auctions (
                auction_id TEXT PRIMARY KEY,
                item TEXT NOT NULL,
                closing_date TEXT NOT NULL,
                min_bid REAL,
                categoria TEXT,
                signature TEXT,
                anonymous_token TEXT,
                seller_anonymous_id TEXT,
                is_mine INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tabela de bids
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bids (
                bid_id TEXT PRIMARY KEY,
                auction_id TEXT NOT NULL,
                value REAL NOT NULL,
                timestamp TEXT NOT NULL,
                signature TEXT,
                anonymous_token TEXT,
                bidder_cert TEXT,
                bidder_anonymous_id TEXT,
                is_mine INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (auction_id) REFERENCES auctions(auction_id)
            )
        """)
        
        # Índices para melhorar performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_auction_closing 
            ON auctions(closing_date)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bid_auction 
            ON bids(auction_id)
        """)
        
        self.conn.commit()
    
    # ==================== AUCTIONS ====================
    
    def save_auction(self, auction: Auction, is_mine=False):
        #Guarda um leilão na base de dados
        max_retries = 5
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                cursor = self.conn.cursor()
                
                cursor.execute("SELECT is_mine FROM auctions WHERE auction_id = ?", (auction.auction_id,))
                existing = cursor.fetchone()
                
                if existing:
                    return auction.auction_id

                cursor.execute("""
                    INSERT INTO auctions 
                    (auction_id, item, closing_date, min_bid, categoria, signature, 
                    anonymous_token, seller_anonymous_id, is_mine)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    auction.auction_id,
                    auction.item,
                    auction.closing_date,
                    auction.min_bid,
                    auction.categoria,  
                    auction.signature,
                    auction.anonymous_token,
                    auction.seller_anonymous_id,
                    1 if is_mine else 0
                ))
                self.conn.commit()
                return auction.auction_id
                
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries - 1:
                    import time
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    raise
    
    def get_auction(self, auction_id: str) -> Optional[Auction]:
        #Obtém um leilão específico por ID
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM auctions WHERE auction_id = ?
        """, (auction_id,))
        
        row = cursor.fetchone()
        if row:
            return self._row_to_auction(row)
        return None
    
    def get_all_auctions(self) -> List[Auction]:
        #Obtém todos os leilões
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM auctions 
            ORDER BY created_at DESC
        """)
        
        return [self._row_to_auction(row) for row in cursor.fetchall()]
    
    def get_my_auctions(self) -> List[Auction]:
        #Obtém apenas os leilões que EU criei
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM auctions 
            WHERE is_mine = 1
            ORDER BY created_at DESC
        """)
        
        return [self._row_to_auction(row) for row in cursor.fetchall()]
    
    def get_active_auctions(self) -> List[Auction]:
        #Obtém leilões ainda ativos 
        from datetime import datetime
        
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()  
        
        cursor.execute("""
            SELECT * FROM auctions 
            WHERE closing_date > ?
            ORDER BY closing_date ASC
        """, (now,))
        
        return [self._row_to_auction(row) for row in cursor.fetchall()]

    def get_closed_auctions(self) -> List[Auction]:
        #Obtém leilões já encerrados
        from datetime import datetime
        
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        
        cursor.execute("""
            SELECT * FROM auctions 
            WHERE closing_date <= ?
            ORDER BY closing_date DESC
        """, (now,))
        
        return [self._row_to_auction(row) for row in cursor.fetchall()]
    
    # ==================== BIDS ====================
    
    def save_bid(self, bid: Bid, is_mine=False):
        #Guarda um bid na base de dados
        max_retries = 5
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO bids 
                    (bid_id, auction_id, value, timestamp, signature, 
                    anonymous_token, bidder_cert, bidder_anonymous_id, is_mine)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    bid.bid_id,
                    bid.auction_id,
                    bid.value,
                    bid.timestamp,
                    bid.signature,
                    bid.anonymous_token,
                    bid.bidder_cert,
                    bid.bidder_anonymous_id,
                    1 if is_mine else 0
                ))
                self.conn.commit()
                return bid.bid_id
                
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries - 1:
                    import time
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    raise
    
    def get_bids_for_auction(self, auction_id: str) -> List[Bid]:
        #Obtém todos os bids de um leilão específico
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM bids 
            WHERE auction_id = ?
            ORDER BY value DESC, timestamp ASC
        """, (auction_id,))
        
        return [self._row_to_bid(row) for row in cursor.fetchall()]
    
    def get_my_bids(self) -> List[Bid]:
        #Obtém apenas os bids que EU fiz
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM bids 
            WHERE is_mine = 1
            ORDER BY timestamp DESC
        """)
        
        return [self._row_to_bid(row) for row in cursor.fetchall()]
    
    def get_winning_bid(self, auction_id: str) -> Optional[Bid]:
        #Obtém o bid vencedor de um leilão. Critério: maior valor, caso empate → timestamp mais antigo
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM bids 
            WHERE auction_id = ?
            ORDER BY value DESC, timestamp ASC
            LIMIT 1
        """, (auction_id,))
        
        row = cursor.fetchone()
        if row:
            return self._row_to_bid(row)
        return None
    
    def get_highest_bid(self, auction_id):
        #Retorna o bid mais alto de um leilão
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM bids 
            WHERE auction_id = ? 
            ORDER BY value DESC 
            LIMIT 1
        """, (auction_id,))
        row = cursor.fetchone()
        return self._row_to_bid(row) if row else None

    def is_my_auction(self, auction_id):
        #Verifica se o leilão é meu
        cursor = self.conn.cursor()
        cursor.execute("SELECT is_mine FROM auctions WHERE auction_id = ?", (auction_id,))
        row = cursor.fetchone()
        return row and row["is_mine"] == 1

    # ==================== HELPERS ====================
    
    def _row_to_auction(self, row) -> Auction:
        #Converte row SQL para objeto Auction
        auction = Auction(
            item=row["item"],
            closing_date=row["closing_date"],
            min_bid=row["min_bid"],
            categoria=row["categoria"] if "categoria" in row.keys() else None  
        )
        auction.auction_id = row["auction_id"]
        auction.signature = row["signature"]
        auction.anonymous_token = row["anonymous_token"] if "anonymous_token" in row.keys() else None
        auction.seller_anonymous_id = row["seller_anonymous_id"]
        return auction
    
    def _row_to_bid(self, row) -> Bid:
        #Converte row SQL para objeto Bid
        bid = Bid(
            auction_id=row["auction_id"],
            value=row["value"]
        )
        bid.bid_id = row["bid_id"]
        bid.timestamp = row["timestamp"]
        bid.signature = row["signature"]
        bid.anonymous_token = row["anonymous_token"] if "anonymous_token" in row.keys() else None
        bid.bidder_cert = row["bidder_cert"]
        bid.bidder_anonymous_id = row["bidder_anonymous_id"]
        return bid
    
    def close(self):
        #Fecha a conexão à base de dados
        if self.conn:
            try:
                self.conn.commit()  # Guarda alterações pendentes
                self.conn.close()
                self.conn = None
            except Exception as e:
                print(f"Error closing database: {e}")