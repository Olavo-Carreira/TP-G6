"""
Blockchain - Cadeia de blocos para registar transações de leilões
"""

from block import Block
from crypto_utils import deserialize_key, verify_signature
import time
import json
import hashlib


class Blockchain:
    """Representa a blockchain do sistema de leilões"""
    
    def __init__(self, server_public_key = None):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2
        self.pending_transactions = []
        self.seen_transaction_hashes = set()  # Prevenir duplicações
        self.server_public_key = server_public_key
        
    def create_genesis_block(self):
        """Criar primeiro bloco da blockchain"""
        return Block(0, "0", 0, [{"type": "genesis"}])
    
    def get_last_block(self):
        """Obter último bloco da blockchain"""
        return self.chain[-1]
    
    def get_last_block_hash(self):
        """Obter hash do último bloco"""
        return self.get_last_block().hash
    
    def get_block(self, index):
        """Buscar um bloco específico"""
        if index < 0 or index >= len(self.chain):
            raise IndexError(f"Bloco {index} não existe")
        
        return self.chain[index]
    
    def verify_trusted_timestamp(self, transaction):
        """Verificar assinatura do timestamp do server"""
        
        if not self.server_public_key:
            print("Sem chave do server - nao e possivel verificar timestamp")
            return True
        
        tx_type = transaction.get('type')
        data = transaction.get('data', {})
        timestamp_sig = data.get('timestamp_signature')
        
        if not timestamp_sig:
            return True
        
        timestamp = transaction.get('timestamp')
        
        
        data_hash = data.get('timestamp_hash')
        if not data_hash:
            return True
        
        message = f"{data_hash}:{timestamp}"
        
        try:
            sig_bytes = bytes.fromhex(timestamp_sig)
            is_valid = verify_signature(message, sig_bytes, self.server_public_key)
            if not is_valid:
                print(f"Timestamp com assinatura invalida")
            return is_valid
        except:
            return False
        
    def validate_transaction(self, transaction):
        """
        ✅ NOVO: Validar transação antes de adicionar
        
        Args:
            transaction: Dicionário com a transação
            
        Returns:
            bool: True se válida, False caso contrário
        """
        
        print(f"DEBUG validate_transaction: type={transaction.get('type')}, timestamp={transaction.get('timestamp')}")
    
        # Verificar estrutura básica
        if not isinstance(transaction, dict):
            return False
        
        if 'type' not in transaction or 'timestamp' not in transaction:
            print("⚠️  Falta type ou timestamp")
            return False

        tx_hash = hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()
        
        if tx_hash in self.seen_transaction_hashes:
            print(f"⚠️  Transação duplicada rejeitada: {tx_hash[:16]}...")
            return False
        
        # Verificar timestamp (não pode ser muito no futuro)
        current_time = time.time()
        if transaction['timestamp'] > current_time + 300:  # 5 min tolerância
            print(f"⚠️  Timestamp inválido: muito no futuro")
            return False
        
        tx_type = transaction.get('type')
        
        # Validações específicas por tipo
        if tx_type == 'USER_REGISTRATION':
            if 'public_key' not in transaction:
                return False
        
        elif tx_type == 'AUCTION_ANNOUNCE':
            data = transaction.get('data', {})
            required_fields = ['auction_id', 'item_description', 'start_time', 'end_time', 'seller_public_key', 'reserve_price_commitment' , 'ring_signature']
            if not all(field in data for field in required_fields):
                missing = [field for field in required_fields if field not in data]
                print(f"Auction invalido - campos em falta {missing}")
                return False
            if not self.verify_trusted_timestamp(transaction):
                print(f"Auction Announce rejeitado - timestamp invalido")
                return False
        
        elif tx_type == 'BID':
            data = transaction.get('data', {})
            required_fields = ['bid_id', 'auction_id', 'bid_value', 'ring_signature']
            if not all(field in data for field in required_fields):
                missing = [field for field in required_fields if field not in data]
                print(f"Auction invalido - campos em falta {missing}")
                return False
            
            if not self.verify_trusted_timestamp(transaction):
                print(f"BID rejeitada - timestamp inválido")
                return False
        
        # Transação válida - adicionar ao set de vistas
        self.seen_transaction_hashes.add(tx_hash)
        
        return True
    
    def add_transaction(self, transaction):
        """
        Adicionar transação às pendentes
        
        ✅ CORRIGIDO: Agora valida antes de adicionar
        
        Args:
            transaction: Transação para adicionar
        """
        if self.validate_transaction(transaction):
            self.pending_transactions.append(transaction)
            return True
        else:
            print(f"⚠️  Transação inválida rejeitada: {transaction.get('type', 'unknown')}")
            return False
        
    def add_block(self, block):
        """
        Adicionar bloco à blockchain
        
        Args:
            block: Bloco para adicionar
        """
        last_block = self.get_last_block()
        
        # Debug detalhado
        if block.previous_hash != last_block.hash:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"❌ CONFLITO DE HASH:")
            logger.error(f"   Bloco recebido #{block.index}")
            logger.error(f"   Previous hash esperado: {block.previous_hash[:16]}...")
            logger.error(f"   Último bloco local: #{last_block.index}")
            logger.error(f"   Hash do último bloco: {last_block.hash[:16]}...")
            logger.error(f"   Chain length: {len(self.chain)}")
            raise ValueError("Previous hash não bate certo")
        
        if not block.verify_integrity():
            raise ValueError("Hash do bloco inválido")
        
        for tx in block.transactions:
            tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
            self.seen_transaction_hashes.add(tx_hash)
        
        self.chain.append(block)
        
    def mine_pending_transactions(self):
        """
        Minerar bloco com as transações pendentes
        
        Returns:
            Block: Bloco minerado ou None se não há transações
        """
        if not self.pending_transactions:
            return None
        
        block = Block(
            index=len(self.chain),
            previous_hash=self.get_last_block().hash,
            timestamp=time.time(),
            transactions=self.pending_transactions
        )
        
        block.mine_block(self.difficulty)
        self.chain.append(block)
        self.pending_transactions = []
        
        return block
    
    def replace_chain(self, new_chain):
        """
        Substituir chain se a nova for maior e válida (consenso)
        
        Args:
            new_chain: Nova chain para comparar
            
        Returns:
            bool: True se substituiu, False caso contrário
        """
        if len(new_chain) > len(self.chain):
            if self.is_chain_valid(new_chain):
                self.chain = new_chain
                
                # Reconstruir set de transações vistas
                import json
                import hashlib
                self.seen_transaction_hashes.clear()
                for block in self.chain:
                    for tx in block.transactions:
                        tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                        self.seen_transaction_hashes.add(tx_hash)
                
                return True
        return False
    
    def is_valid(self):
        """Verificar integridade da chain local"""
        return self.is_chain_valid(self.chain)
    
    def is_chain_valid(self, chain):
        """
        Validar uma chain
        
        Args:
            chain: Lista de blocos para validar
            
        Returns:
            bool: True se válida, False caso contrário
        """
        for i in range(1, len(chain)):
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
            
            # Reconstruir set de transações vistas
            import hashlib
            self.seen_transaction_hashes.clear()
            for block in self.chain:
                for tx in block.transactions:
                    tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                    self.seen_transaction_hashes.add(tx_hash)
            
        except FileNotFoundError:
            print("Ficheiro não existe, a usar genesis block")
            self.chain = [self.create_genesis_block()]
    
    def get_transactions_by_type(self, t_type):
        """
        Buscar transações por tipo
        
        Args:
            t_type: Tipo de transação ('BID', 'AUCTION_ANNOUNCE', etc)
            
        Returns:
            list: Lista de transações do tipo especificado
        """
        results = []
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('type') == t_type:
                    results.append(tx)
        return results
    
    def get_all_user_keys(self):
        """
        Extrair chaves públicas de users registados
        
        ✅ CORRIGIDO: Agora busca também em pending_transactions!
        
        Returns:
            list: Lista de chaves públicas
        """
        # Buscar em blocos minerados
        user_reg_txs = self.get_transactions_by_type('USER_REGISTRATION')
        
        # ✅ TAMBÉM buscar em pending transactions!
        for tx in self.pending_transactions:
            if tx.get('type') == 'USER_REGISTRATION':
                user_reg_txs.append(tx)

        keys = []
        seen_keys = set()

        for tx in user_reg_txs:
            pk_str = tx['public_key']

            if pk_str not in seen_keys:
                pk_bytes = pk_str.encode('utf-8')
                pk = deserialize_key(pk_bytes, is_private=False)
                keys.append(pk)
                seen_keys.add(pk_str)

        return keys