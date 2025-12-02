import hashlib
import json
import time

class Block:
    """Class that represents a block in the blockchain"""
    
    def __init__ (self, index, previous_hash, timestamp, transactions, nonce = 0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions # list of dicts
        self.nonce = nonce
        self.hash = self.calculate_hash()
        
    def calculate_hash(self):
        """Calculate SHA256 of the block"""
        
        block_string = json.dumps({
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'nonce': self.nonce
        }, sort_keys = True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    # TODO maybe later add something cooler instead of starting with 0
    
    def mine_block(self, difficulty):
        """Proof-of-Work: find the nonce that makes hash start with 0 times the difficulty"""
        
        target = '0' * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        print(f"Block mined: {self.hash}")
    
    def verify_integrity(self):
        """Verify if hash is correct"""
        calculated = self.calculate_hash()
        return calculated == self.hash

    def save_to_file(self, filepath):
        """Save block to JSON file"""
        with open(filepath, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
    
    @staticmethod
    def load_from_file(filepath):
        """Load block from file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return Block.from_dict(data)

    def to_dict(self):
        """Serialize to JSON"""
        
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'nonce': self.nonce,
            'hash': self.hash
        }
    
    @staticmethod
    def from_dict(data):
        """Deserialize from JSON"""
        
        block = Block(
            data['index'],
            data['previous_hash'],
            data['timestamp'],
            data['transactions'],
            data['nonce']
        )
        block.hash = data['hash']
        return block

