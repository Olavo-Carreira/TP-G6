from block import Block
import time

class Blockchain:
    """Classe que representa a blockchain"""
    
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2
        self.pending_transactions = []
        
    def create_genesis_block(self):
        """Primeiro bloco da blockchain"""
        
        return Block(0, "0", 0, [{"type": "genesis"}])
    
    def get_last_block(self):
        """Ultimo bloco da blockchain"""
        
        return self.chain[-1]
    
    def get_last_block_hash(self):
        """Hash do ultimo bloco"""
        
        return self.get_last_block().hash
    
    def get_block(self, index):
        """Buscar um bloco especifico"""
        
        if index < 0 or index >= len(self.chain):
            raise IndexError(f"Bloco {index} nao existe")
        
        return self.chain[index]
    
    def add_transaction(self, transaction):
        """Adicionar transicacao as pendentes"""
        
        self.pending_transactions.append(transaction)
        
    def add_block(self, block):
        """Adicionar bloco a blockchain"""
        
        if block.previous_hash != self.get_last_block().hash:
            raise ValueError("Previous hash nao bate certo")
        
        if not block.verify_integrity():
            raise ValueError("Hash do bloco invalido")
        
        self.chain.append(block)
        
    def mine_pending_transactions(self):
        """Minerar bloco com as transações pendentes"""
        
        if not self.pending_transactions:
            return None
        
        block = Block(
            index = len(self.chain),
            previous_hash = self.get_last_block().hash,
            timestamp = time.time(),
            transactions = self.pending_transactions
        )
        
        block.mine_block(self.difficulty)
        self.chain.append(block)
        self.pending_transactions = []
        
        return block
    
    def replace_chain(self, new_chain):
        """Mudar a chain caso seja maior (consenso)"""

        if len(new_chain) > len(self.chain):
            if self.is_chain_valid(new_chain):
                self.chain = new_chain
                return True
        return False
    
    
            
    def is_valid(self):
        """Verificar integridade da chain"""
        
        return self.is_chain_valid(self.chain)
    
    def is_chain_valid(self, chain):
        """Valida uma dada chain"""
        
        for i in range (1, len(chain)):
            current = chain[i]
            previous = chain[i-1]
            
            if current.hash != current.calculate_hash():
                return False
            
            if current.previous_hash != previous.hash:
                return False
        
        return True
            
    def save_to_disk(self, filepath='blockchain.json'):
        """Guardar chain completa em disco"""
        import json
    
        chain_data = [block.to_dict() for block in self.chain]
    
        with open(filepath, 'w') as f:
            json.dump(chain_data, f, indent=2)

    def load_from_disk(self, filepath='blockchain.json'):
        """Carregar chain de disco"""
        import json
        from block import Block
        
        try:
            with open(filepath, 'r') as f:
                chain_data = json.load(f)
            
            self.chain = [Block.from_dict(block_dict) for block_dict in chain_data]
            
        except FileNotFoundError:
            print("Ficheiro não existe, a usar genesis block")
            self.chain = [self.create_genesis_block()]
            
    
    # Secalhar n é preciso esta
    # TODO get_transactions_by_auction(self, auction_id)
    def get_transactions_by_type(self, t_type):
        """Buscar transacoes por tipo"""
        
        results = []
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('type') == t_type:
                    results.append(tx)
        return results

if __name__ == '__main__':
    bc = Blockchain()
    
    # Adicionar transações
    bc.add_transaction({'type': 'BID', 'value': 100})
    bc.add_transaction({'type': 'BID', 'value': 150})
    
    # Minerar
    print("Minerando bloco...")
    bc.mine_pending_transactions()
    
    # Verificar
    print(f"Chain válida? {bc.is_valid()}")
    print(f"Blocos na chain: {len(bc.chain)}")