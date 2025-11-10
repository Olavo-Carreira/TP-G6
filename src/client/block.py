import hashlib
import json
import time

class Block:
    """Classe que representa um bloco na blockchain"""
    
    def __init__ (self, index, previous_hash, timestamp, transactions, nonce = 0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions #lista de dicts
        self.nonce = nonce
        self.hash = self.calculate_hash()
        
    def calculate_hash(self):
        """Calcula SHA256 do bloco"""
        
        block_string = json.dumps({
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'nonce': self.nonce
        }, sort_keys = True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    #TODO secalhar depois meter algo mais giro em vez de ser comecar por 0
    
    def mine_block(self, difficulty):
        """Proof-of-Work: encontrar o nonce que faça hash começar com 0 vezes a difficuldade"""
        
        target = '0' * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        print(f"Block mined: {self.hash}")
    
    def verify_integrity(self):
        """Verificar se hash está correto"""
        calculated = self.calculate_hash()
        return calculated == self.hash

    def save_to_file(self, filepath):
        """Guardar bloco em ficheiro JSON"""
        with open(filepath, 'w') as f:
                json.dump(self.to_dict(), f, indent=2)
    
    @staticmethod
    def load_from_file(filepath):
        """Carregar bloco de ficheiro"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return Block.from_dict(data)

    def to_dict(self):
        """Serializar para Json"""
        
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
        """Deserializar de Json"""
        
        block = Block(
            data['index'],
            data['previous_hash'],
            data['timestamp'],
            data['transactions'],
            data['nonce']
        )
        block.hash = data['hash']
        return block
    
if __name__ == '__main__':
    block = Block(
        index=1,
        previous_hash='0' * 64,
        timestamp=time.time(),
        transactions=[
            {'type': 'test', 'data': 'hello world'}
        ]
    )
    
    print(f"Hash antes mining: {block.hash}")
    
    # Minerar (difficulty 2 = precisa começar com "00")
    block.mine_block(difficulty=2)
    
    print(f"Hash depois mining: {block.hash}")
    print(f"Nonce encontrado: {block.nonce}")