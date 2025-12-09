import os
import hashlib
import json
from pathlib import Path

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

def save_secret_locally(secret_data, username):
    """Save secret data for specific user"""
    # Get user directory
    user_dir = Path.home() / '.auction_system' / username.lower()
    user_dir.mkdir(parents=True, exist_ok=True)
    
    secrets_file = user_dir / 'secrets.json'
    
    # Load existing secrets
    try:
        if secrets_file.exists():
            existing = json.loads(secrets_file.read_text())
        else:
            existing = []
    except (json.JSONDecodeError, IOError):
        existing = []
    
    # Append new secret
    existing.append(secret_data)
    
    # Save back
    secrets_file.write_text(json.dumps(existing, indent=2))


def load_all_secrets(username):
    """Load all secrets for user"""
    secrets_file = Path.home() / '.auction_system' / username.lower() / 'secrets.json'
    
    if not secrets_file.exists():
        return []
    
    try:
        return json.loads(secrets_file.read_text())
    except (json.JSONDecodeError, IOError):
        return []


def load_secret_for_reveal(auction_id, username):
    """Load secret data for specific auction"""
    all_secrets = load_all_secrets(username)
    
    for secret in all_secrets:
        if secret.get("auction_id") == auction_id:
            return secret
    
    return None

def save_won_auction(auction_id, username):
    """Save won auction"""
    user_dir = Path.home() / '.auction_system' / username.lower()
    user_dir.mkdir(parents = True, exist_ok = True)
    
    won_file = user_dir / 'won_auctions.json'
    
    try:
        if won_file.exists():
            existing = json.loads(won_file.read_text())
        else:
            existing = []
    except (json.JSONDecodeError, IOError):
        existing = []
    
    if auction_id not in existing:
        existing.append(auction_id)
    
    won_file.write_text(json.dumps(existing, indent=2))
    
def load_won_auctions(username):
    """Load won auctions"""
    won_file = Path.home() / '.auction_system' / username.lower() / 'won_auctions.json'
    
    if not won_file.exists():
        return set()
    
    try:
        data = json.loads(won_file.read_text())
        return set(data)
    except (json.JSONDecodeError, IOError):
        return set()
        
def serialize_commitment(commitment_data):
    """Convert commitment to JSON (to save/send)"""
    
    return json.dumps(commitment_data)


def deserialize_commitment(commitment_json):
    """Convert JSON back to dict"""
    
    return json.loads(commitment_json)

