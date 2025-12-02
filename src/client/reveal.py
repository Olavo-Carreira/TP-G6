import json
import time
from typing import Dict
from crypto_utils import serialize_key, encrypt_for_dest, deserialize_key

class IdentityReveal:
    
    def __init__ (self, auction_id, role, public_key, bid_commitment, reveal_timestamp):
        
        self.auction_id = auction_id
        self.role = role # Winner or seller
        self.public_key = public_key
        self.bid_commitment = bid_commitment  
        self.reveal_timestamp = reveal_timestamp
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'auction_id': self.auction_id,
            'role': self.role,
            'public_key': self.public_key,
            'bid_commitment': self.bid_commitment,
            'reveal_timestamp': self.reveal_timestamp
        }
    
    @staticmethod
    def from_dict(data: Dict):
        """Create from dictionary"""
        return IdentityReveal(
            auction_id=data['auction_id'],
            role=data['role'],
            public_key=data['public_key'],
            bid_commitment=data.get('bid_commitment'),
            reveal_timestamp=data['reveal_timestamp']
        )
    
    def to_blockchain_transaction(self):
        """Convert to blockchain transaction"""
        return {
            'type': 'identity_reveal',
            'data': self.to_dict(),
            'timestamp': self.reveal_timestamp
        }
    
    def to_encrypted_message(self, dest_pubkey):
        """Create encrypted message for recipient"""
        
        if isinstance(dest_pubkey, str):
            dest_pubkey = deserialize_key(dest_pubkey.encode(), is_private = False)
        elif isinstance(dest_pubkey, bytes):
            dest_pubkey = deserialize_key(dest_pubkey, is_private = False)
        
        reveal_data = self.to_dict()
        encrypted_package = encrypt_for_dest(reveal_data, dest_pubkey)
        
        encrypted_package['type'] = 'ENCRYPTED_REVEAL'
        encrypted_package['timestamp'] = self.reveal_timestamp
        
        return encrypted_package
        
        
class IdentityRevealManager:
    """Manages identity reveals for auctions"""
    
    def __init__ (self):
        self.identity_reveals: Dict[str, Dict[str, IdentityReveal]] = {}
        # auction_id -> {seller : IdentityReveal, winner : IdentityReveal}
        
    def reveal_seller_identity(self, auction_id, seller_public_key):
        """Reveal seller identity"""
        
        pubkey_bytes = serialize_key(seller_public_key, is_private = False)
        
        reveal = IdentityReveal(
            auction_id = auction_id,
            role = "seller",
            public_key = pubkey_bytes.decode() if isinstance(pubkey_bytes, bytes) else pubkey_bytes,
            bid_commitment = None,
            reveal_timestamp = time.time()
        )
        
        if auction_id not in self.identity_reveals:
            self.identity_reveals[auction_id] = {}
            
        self.identity_reveals[auction_id]["seller"] = reveal
        
        return reveal
    
    def reveal_winner_identity(self, auction_id, winner_public_key, winning_bid_commitment):
        """Reveal winner identity"""
        
        pubkey_bytes = serialize_key(winner_public_key, is_private = False)
        
        reveal = IdentityReveal(
            auction_id = auction_id,
            role = "winner",
            public_key = pubkey_bytes.decode() if isinstance(pubkey_bytes, bytes) else pubkey_bytes,
            bid_commitment = winning_bid_commitment,
            reveal_timestamp = time.time()
        )
        
        if auction_id not in self.identity_reveals:
            self.identity_reveals[auction_id] = {}
            
        self.identity_reveals[auction_id]["winner"] = reveal
        
        return reveal
    
    def get_seller_identity(self, auction_id):
        """Get seller identity reveal"""
        return self.identity_reveals.get(auction_id, {}).get("seller")
    
    def get_winner_identity(self, auction_id):
        """Get winner identity reveal"""
        return self.identity_reveals.get(auction_id, {}).get("winner")

    def are_identities_revealed(self,auction_id):
        """Check if both identities are revealed"""
        reveals = self.identity_reveals.get(auction_id, {})
        return "seller" in reveals and "winner" in reveals