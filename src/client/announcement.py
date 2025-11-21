import json
import hashlib
from typing import Dict
import time


from crypto_utils import serialize_key
from commitement import create_commitment
from ring import ring_sign, ring_verify


class AuctionAnnouncement:
    
    def __init__ (self, auction_id, seller_public_key, item_description, reserve_price_commitment, start_time, 
                end_time, timestamp, ring_signature):
        
        self.auction_id = auction_id
        self.seller_public_key = seller_public_key
        self.item_description = item_description
        self.reserve_price_commitment = reserve_price_commitment
        self.start_time = start_time
        self.end_time = end_time
        self.timestamp = timestamp
        self.ring_signature = ring_signature
        
    @staticmethod
    def create(seller_private_key,seller_public_key,item_description,reserve_price,duration_seconds,ring_public_keys):
        """Cria anuncio"""

        
        # Generate unique auction ID
        seller_pubkey_bytes = serialize_key(seller_public_key, is_private=False)
        auction_id = hashlib.sha256(
            f"{seller_pubkey_bytes.hex()}{item_description}{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Commit to reserve price
        _, private_commitment = create_commitment(auction_id, reserve_price)
        reserve_commitment = private_commitment['commitment']
        reserve_nonce = private_commitment['nonce']
        
        current_time = time.time()
        
        # Create announcement (without ring signature first)
        announcement = AuctionAnnouncement(
            auction_id=auction_id,
            seller_public_key=seller_pubkey_bytes.decode() if isinstance(seller_pubkey_bytes, bytes) else seller_pubkey_bytes,
            item_description=item_description,
            reserve_price_commitment=reserve_commitment,
            start_time=current_time,
            end_time=current_time + duration_seconds,
            timestamp=current_time,
            ring_signature={}  # Placeholder
        )
        
        # Add ring signature
        message = announcement.compute_hash()
        signature = ring_sign(message, seller_private_key, ring_public_keys)
        announcement.ring_signature = signature
        
        return announcement, reserve_nonce
    
    def to_dict(self):
        """Converter para dicionario"""
        
        return {
            'auction_id': self.auction_id,
            'seller_public_key': self.seller_public_key,
            'item_description': self.item_description,
            'reserve_price_commitment': self.reserve_price_commitment,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'timestamp': self.timestamp,
            'ring_signature': self.ring_signature
        }
    
    @staticmethod
    def from_dict(data: Dict):
        """Criar do dicionario"""
        
        return AuctionAnnouncement(
            auction_id = data['auction_id'],
            seller_public_key = data['seller_public_key'],
            item_description = data['item_description'],
            reserve_price_commitment = data['reserve_price_commitment'],
            start_time = data['start_time'],
            end_time = data['end_time'],
            timestamp = data['timestamp'],
            ring_signature = data['ring_signature']
        )
        
    def compute_hash(self):
        """Hash do announcement"""
        
        data = {
            'auction_id': self.auction_id,
            'seller_public_key': self.seller_public_key,
            'item_description': self.item_description,
            'reserve_price_commitment': self.reserve_price_commitment,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'timestamp': self.timestamp
        }
        
        return hashlib.sha256(json.dumps(data, sort_keys = True).encode()).hexdigest()
    
    def verify(self, ring_public_keys):
        """Verifica anuncio"""
        
        message = self.compute_hash()
        if not ring_verify(message, self.ring_signature, ring_public_keys):
            return False
        
        if self.timestamp > time.time() + 300: # Tolerancia
            return False
        
        if self.end_time <= self.start_time:
            return False
        
        return True
    
    def to_blockchain_transaction(self):
        
        return {
            'type': 'AUCTION_ANNOUNCE',
            'data': self.to_dict(),
            'timestamp': self.timestamp
        }
        