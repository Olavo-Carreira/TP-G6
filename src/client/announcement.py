import json
import hashlib
from typing import Dict
import time
from crypto_utils import serialize_key, deserialize_key, verify_signature
from commitement import create_commitment
from ring import ring_sign, ring_verify


class AuctionAnnouncement:
    
    def __init__ (self, auction_id, item_description, reserve_price_commitment, start_time, 
                end_time, timestamp, ring_signature, timestamp_signature = None, timestamp_hash = None, ring_public_keys = None):
        
        self.auction_id = auction_id
        self.item_description = item_description
        self.reserve_price_commitment = reserve_price_commitment
        self.start_time = start_time
        self.end_time = end_time
        self.timestamp = timestamp
        self.ring_signature = ring_signature
        self.timestamp_signature = timestamp_signature
        self.timestamp_hash = timestamp_hash
        self.ring_public_keys = ring_public_keys
        
    @staticmethod
    def create(seller_private_key,item_description,reserve_price,duration_seconds,ring_public_keys, start_timestamp = None, timestamp_signature = None, timestamp_hash = None):
        """Create announcement"""

        seller_public_key = seller_private_key.public_key()
        
        # Generate unique auction ID
        seller_pubkey_bytes = serialize_key(seller_public_key, is_private=False)
        auction_id = hashlib.sha256(
            f"{seller_pubkey_bytes.hex()}{item_description}{time.time()}".encode()
        ).hexdigest()[:16]
        
        # Commit to reserve price
        _, private_commitment = create_commitment(auction_id, reserve_price)
        reserve_commitment = private_commitment['commitment']
        reserve_nonce = private_commitment['nonce']
        
        if start_timestamp is None or timestamp_signature is None:
            raise ValueError("Trusted timestamp is required! Cannot create announcement without server timestamp.")    
        
        current_time = start_timestamp
        
        serialized_ring = []
        for pk in ring_public_keys:
            if isinstance(pk,str):
                serialized_ring.append(pk)
            elif isinstance(pk,bytes):
                serialized_ring.append(pk.decode())
            else:
                pk_bytes = serialize_key(pk, is_private = False)
                serialized_ring.append(pk_bytes.decode())
        
        # Create announcement (without ring signature first)
        announcement = AuctionAnnouncement(
            auction_id=auction_id,
            item_description=item_description,
            reserve_price_commitment=reserve_commitment,
            start_time=current_time,
            end_time=current_time + duration_seconds,
            timestamp=current_time,
            ring_signature = {},
            timestamp_signature = timestamp_signature,
            timestamp_hash = timestamp_hash,
            ring_public_keys = serialized_ring)
        
        # Add ring signature
        message = announcement.compute_hash()
        signature = ring_sign(message, seller_private_key, ring_public_keys)
        announcement.ring_signature = signature
        
        return announcement, reserve_nonce
    
    def to_dict(self):
        """Convert to dictionary"""
        
        return {
            'auction_id': self.auction_id,
            'item_description': self.item_description,
            'reserve_price_commitment': self.reserve_price_commitment,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'timestamp': self.timestamp,
            'ring_signature': self.ring_signature,
            'timestamp_signature': self.timestamp_signature,
            'timestamp_hash': self.timestamp_hash,
            'ring_public_keys': self.ring_public_keys
        }
    
    @staticmethod
    def from_dict(data: Dict):
        """Create from dictionary"""
        
        return AuctionAnnouncement(
            auction_id = data['auction_id'],
            item_description = data['item_description'],
            reserve_price_commitment = data['reserve_price_commitment'],
            start_time = data['start_time'],
            end_time = data['end_time'],
            timestamp = data['timestamp'],
            ring_signature = data['ring_signature'],
            timestamp_signature = data['timestamp_signature'],
            timestamp_hash = data['timestamp_hash'],
            ring_public_keys = data['ring_public_keys']
        )
        
    def compute_hash(self):
        """Hash of the announcement"""
        
        data = {
            'auction_id': self.auction_id,
            'item_description': self.item_description,
            'reserve_price_commitment': self.reserve_price_commitment,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'timestamp': self.timestamp
        }
        
        return hashlib.sha256(json.dumps(data, sort_keys = True).encode()).hexdigest()
    
    def verify(self, ring_public_keys, server_public_key=None):
        """Verify announcement"""
        
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
        
        message = self.compute_hash()

        ring_valid = ring_verify(message, self.ring_signature, ring_public_keys)
        print(f"🔍 DEBUG verify: Ring signature valid? {ring_valid}")
    
        if not ring_valid:
            return False

        # TIAGO
        if server_public_key and self.timestamp_signature:
            timestamp_message = f"{self.timestamp_hash}:{self.timestamp}"
            try:
                sig_bytes = bytes.fromhex(self.timestamp_signature)
                if not verify_signature(timestamp_message, sig_bytes, server_public_key):
                    print(f"🔍 DEBUG verify: Invalid server timestamp signature!")
                    return False
            except Exception as e:
                print(f"🔍 DEBUG verify: Error verifying timestamp: {e}")
                return False
        
        # Check timestamp not too far in the future
        if self.timestamp > time.time() + 300: # Tolerance
            print(f"🔍 DEBUG verify: Timestamp too far in the future!")
            return False
        
        if self.end_time <= self.start_time:
            print(f"🔍 DEBUG verify: end_time <= start_time!")
            return False
        
        return True
    
    def to_blockchain_transaction(self):
        data_dict = self.to_dict()
        timestamp = data_dict.pop('timestamp')
        
        return {
            'type': 'AUCTION_ANNOUNCE',
            'data': data_dict,
            'timestamp': timestamp
        }
