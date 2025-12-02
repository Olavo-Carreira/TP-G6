import os
import hashlib
import json

def create_commitment(auction_id, value):
    """Create commitment (hash of bid + nonce)"""
    
    nonce_bytes = os.urandom(32)
    nonce_hex = nonce_bytes.hex()
    
    data_str = f"{auction_id}:{value}:{nonce_hex}"
    data_bytes = data_str.encode("utf-8")
    
    hash_hex = hashlib.sha256(data_bytes).hexdigest()
    
    public_commitment = {
        "commitment": hash_hex,
        "auction_id": auction_id
    }
    private_commitment = {
        "commitment": hash_hex,
        "nonce": nonce_hex,
        "bid_value": value,
        "auction_id": auction_id
    }
    
    return public_commitment, private_commitment

def verify_commitment(commitment_hash, value, nonce, auction_id):
    """Verify that commitment matches revealed data"""
    
    data_str = f"{auction_id}:{value}:{nonce}"
    data_bytes = data_str.encode("utf-8")
    recomputed_hash = hashlib.sha256(data_bytes).hexdigest()
    
    return recomputed_hash == commitment_hash   

def save_secret_locally(secret_data, filename="my_secrets.json"):
    """Save secret data"""
    
    try:
        with open(filename, 'r') as f:
            all_bids = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        all_bids = []
    
    all_bids.append(secret_data)
    
    with open(filename, 'w') as f:
        json.dump(all_bids, f, indent=2)

def load_secret_for_reveal(auction_id, filename="my_secrets.json"):
    """Load secret data"""
    
    try:
        with open(filename, 'r') as f:
            all_bids = json.load(f)
        
        for bid in all_bids:
            if bid["auction_id"] == auction_id:
                return bid
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    
    return None
        
def serialize_commitment(commitment_data):
    """Convert commitment to JSON (to save/send)"""
    
    return json.dumps(commitment_data)


def deserialize_commitment(commitment_json):
    """Convert JSON back to dict"""
    
    return json.loads(commitment_json)

