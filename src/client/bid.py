import json
import hashlib
import time
from typing import Dict
from commitement import create_commitment, verify_commitment
from ring import ring_sign, ring_verify
from crypto_utils import deserialize_key, serialize_key


class Bid:
    
    def __init__(self, bid_id, auction_id, bid_commitment, bid_value, bid_nonce, timestamp, ring_signature, timestamp_signature = None, timestamp_hash = None, ring_public_keys = None):
        self.bid_id = bid_id
        self.auction_id = auction_id
        self.bid_commitment = bid_commitment
        self.bid_value = bid_value
        self.bid_nonce = bid_nonce
        self.timestamp = timestamp
        self.ring_signature = ring_signature
        self.timestamp_signature = timestamp_signature
        self.timestamp_hash = timestamp_hash
        self.ring_public_keys = ring_public_keys
        
    @staticmethod
    def create(auction_id, bidder_private_key, bid_amount,ring_public_keys, bid_timestamp = None, timestamp_signature = None, timestamp_hash = None):
        """"Create a bid"""
        
        if bid_timestamp is None or timestamp_signature is None:
            raise ValueError("Trusted timestamp is required! Cannot create bid without server timestamp.")
        
        current_time = bid_timestamp
        
        bid_id = hashlib.sha256(
            f"{auction_id}{bid_amount}{current_time}".encode()
        ).hexdigest()[:16]
        
        _, private_commitment = create_commitment(auction_id, bid_amount)
        bid_commitment = private_commitment['commitment']
        bid_nonce = private_commitment['nonce']
        
        serialized_ring = []
        for pk in ring_public_keys:
            if isinstance(pk, str):
                serialized_ring.append(pk)
            elif isinstance(pk, bytes):
                serialized_ring.append(pk.decode())
            else:
                pk_bytes = serialize_key(pk, is_private=False)
                serialized_ring.append(pk_bytes.decode())
        
        bid = Bid(
            bid_id=bid_id,
            auction_id=auction_id,
            bid_commitment=bid_commitment,
            bid_value = bid_amount,
            bid_nonce = bid_nonce,
            timestamp=current_time,
            ring_signature={},
            timestamp_signature = timestamp_signature,
            timestamp_hash = timestamp_hash,
            ring_public_keys = serialized_ring
            )
        
        message = bid.compute_hash()
        signature = ring_sign(message, bidder_private_key, ring_public_keys)
        bid.ring_signature = signature
        
        return bid
        
    def to_dict(self):
        """Serialize to dictionary"""
        
        return {
            'bid_id': self.bid_id,
            'auction_id': self.auction_id,
            'bid_commitment': self.bid_commitment,
            'bid_value': self.bid_value,
            'bid_nonce': self.bid_nonce,
            'timestamp': self.timestamp,
            'ring_signature': self.ring_signature,
            'timestamp_signature': self.timestamp_signature,
            'timestamp_hash': self.timestamp_hash,
            'ring_public_keys': self.ring_public_keys
        }
    
    @staticmethod
    def from_dict(data: Dict):
        """Create bid from dictionary"""
        
        return Bid (
            bid_id = data['bid_id'],
            auction_id = data['auction_id'],
            bid_commitment = data['bid_commitment'],
            bid_value = data['bid_value'],
            bid_nonce = data['bid_nonce'],
            timestamp = data['timestamp'],
            ring_signature = data['ring_signature'],
            timestamp_signature = data['timestamp_signature'],
            timestamp_hash = data['timestamp_hash'],
            ring_public_keys = data['ring_public_keys']
        )
        
    def compute_hash(self):
        """Hash of the bid"""
        
        data = {
            'bid_id': self.bid_id,
            'auction_id': self.auction_id,
            'bid_commitment': self.bid_commitment,
            'timestamp': self.timestamp
        }
        
        return hashlib.sha256(json.dumps(data, sort_keys = True).encode()).hexdigest()
    
    def verify(self, auction_start_time, auction_end_time, ring_public_keys = None):
        """Verify the bid"""
        
        if self.timestamp < auction_start_time or self.timestamp > auction_end_time:
            return False
        
        message = self.compute_hash()
        
        if ring_public_keys is None:
            if self.ring_public_keys is None:
                return False
            ring_public_keys = self.ring_public_keys
            
        keys_to_verify = []
        for key in ring_public_keys:
            if isinstance(key,str):
                keys_to_verify.append(key.encode())
            else:
                keys_to_verify.append(serialize_key(key, is_private = False))
        
        if not ring_verify(message, self.ring_signature, ring_public_keys):
            return False
        
        if not verify_commitment(self.bid_commitment, self.bid_value, self.bid_nonce, self.auction_id):
            return False
        
        return True
    
    def to_blockchain_transaction(self):
        """Blockchain format"""
        
        return {
            'type': 'BID',
            'data': self.to_dict(),
            'timestamp': self.timestamp
        }
