import json
import hashlib
import time
from typing import Dict

from commitement import create_commitment, verify_commitment
from ring import ring_sign, ring_verify


class Bid:
    
    def __init__(self, bid_id, auction_id, bid_commitment, bid_value, bid_nonce, timestamp, ring_signature, timestamp_signature = None, timestamp_hash = None):
        self.bid_id = bid_id
        self.auction_id = auction_id
        self.bid_commitment = bid_commitment
        self.bid_value = bid_value
        self.bid_nonce = bid_nonce
        self.timestamp = timestamp
        self.ring_signature = ring_signature
        self.timestamp_signature = timestamp_signature
        self.timestamp_hash = timestamp_hash
        
    @staticmethod
    def create(auction_id, bidder_private_key, bidder_public_key, bid_amount,ring_public_keys, bid_timestamp = None, timestamp_signature = None, timestamp_hash = None):
        """"Cria uma bid"""
        
        current_time = bid_timestamp if bid_timestamp else time.time()
        
        bid_id = hashlib.sha256(
            f"{auction_id}{bid_amount}{current_time}".encode()
        ).hexdigest()[:16]
        
        _, private_commitment = create_commitment(auction_id, bid_amount)
        bid_commitment = private_commitment['commitment']
        bid_nonce = private_commitment['nonce']
        
        bid = Bid(
            bid_id=bid_id,
            auction_id=auction_id,
            bid_commitment=bid_commitment,
            bid_value = bid_amount,
            bid_nonce = bid_nonce,
            timestamp=current_time,
            ring_signature={},
            timestamp_signature = timestamp_signature,
            timestamp_hash = timestamp_hash
        )
        
        message = bid.compute_hash()
        signature = ring_sign(message, bidder_private_key, ring_public_keys)
        bid.ring_signature = signature
        
        return bid
        
    def to_dict(self):
        """Serealizar para dicionario"""
        
        return {
            'bid_id': self.bid_id,
            'auction_id': self.auction_id,
            'bid_commitment': self.bid_commitment,
            'bid_value': self.bid_value,
            'bid_nonce': self.bid_nonce,
            'timestamp': self.timestamp,
            'ring_signature': self.ring_signature,
            'timestamp_signature': self.timestamp_signature,
            'timestamp_hash': self.timestamp_hash
        }
    
    @staticmethod
    def from_dict(data: Dict):
        """Criar bid do dicionario"""
        
        return Bid (
            bid_id = data['bid_id'],
            auction_id = data['auction_id'],
            bid_commitment = data['bid_commitment'],
            bid_value = data['bid_value'],
            bid_nonce = data['bid_nonce'],
            timestamp = data['timestamp'],
            ring_signature = data['ring_signature'],
            timestamp_signature = data['timestamp_signature'],
            timestamp_hash = data['timestamp_hash']
        )
        
    def compute_hash(self):
        """Hash da bid"""
        
        data = {
            'bid_id': self.bid_id,
            'auction_id': self.auction_id,
            'bid_commitment': self.bid_commitment,
            'timestamp': self.timestamp
        }
        
        return hashlib.sha256(json.dumps(data, sort_keys = True).encode()).hexdigest()
    
    def verify(self, auction_start_time, auction_end_time, ring_public_keys):
        """Verifica a bid"""
        
        if self.timestamp < auction_start_time or self.timestamp > auction_end_time:
            return False
        
        message = self.compute_hash()
        
        if not ring_verify(message, self.ring_signature, ring_public_keys):
            return False
        
        if not verify_commitment(self.bid_commitment, self.bid_value, self.bid_nonce, self.auction_id):
            return False
        
        return True
    
    def to_blockchain_transaction(self):
        """Formato de blockchain"""
        
        return {
            'type': 'BID',
            'data': self.to_dict(),
            'timestamp': self.timestamp
        }
        