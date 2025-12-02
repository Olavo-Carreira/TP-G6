from block import Block
from crypto_utils import deserialize_key, verify_signature
import time
import json
import hashlib


class Blockchain:
    """Represents the auction system blockchain"""
    
    def __init__(self, server_public_key = None):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2
        self.pending_transactions = []
        self.seen_transaction_hashes = set()  # Prevent duplicates
        self.server_public_key = server_public_key
        self.used_key_images = set()
        
    def create_genesis_block(self):
        """Create first block of the blockchain"""
        return Block(0, "0", 0, [{"type": "genesis"}])
    
    def get_last_block(self):
        """Get last block of the blockchain"""
        return self.chain[-1]
    
    def get_last_block_hash(self):
        """Get hash of the last block"""
        return self.get_last_block().hash
    
    def get_block(self, index):
        """Fetch a specific block"""
        if index < 0 or index >= len(self.chain):
            raise IndexError(f"Block {index} does not exist")
        
        return self.chain[index]
    
    def verify_trusted_timestamp(self, transaction):
        """Verify server timestamp signature"""
        
        if not self.server_public_key:
            print("No server key - cannot verify timestamp")
            return False
        
        tx_type = transaction.get('type')
        data = transaction.get('data', {})
        timestamp_sig = data.get('timestamp_signature')
        
        if not timestamp_sig:
            return False
        
        timestamp = transaction.get('timestamp')
        data_hash = data.get('timestamp_hash')
        
        if not data_hash:
            return False
        
        message = f"{data_hash}:{timestamp}"
        
        try:
            sig_bytes = bytes.fromhex(timestamp_sig)
            is_valid = verify_signature(message, sig_bytes, self.server_public_key)
            if not is_valid:
                print(f"Timestamp with invalid signature")
                return False
        except:
            return False
        
        return True
        
    def validate_transaction(self, transaction):
        """
        Validate transaction before adding
        """
        
        print(f"DEBUG validate_transaction: type={transaction.get('type')}, timestamp={transaction.get('timestamp')}")
    
        # Verify basic structure
        if not isinstance(transaction, dict):
            return False
        
        if 'type' not in transaction or 'timestamp' not in transaction:
            print("⚠️  Missing type or timestamp")
            return False

        tx_hash = hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()
        
        if tx_hash in self.seen_transaction_hashes:
            print(f"⚠️  Duplicate transaction rejected: {tx_hash[:16]}...")
            return False
        
        # Verify timestamp (cannot be too far in the future)
        current_time = time.time()
        if transaction['timestamp'] > current_time + 300:  # 5 min tolerance
            print(f"⚠️  Invalid timestamp: too far in the future")
            return False
        
        tx_type = transaction.get('type')
        
        if tx_type in ['AUCTION_ANNOUNCE', 'BID']:
            data = transaction.get('data', {})
            ring_sig = data.get('ring_signature', {})
            key_image = ring_sig.get('key_image')
            
            if key_image and key_image in self.used_key_images:
                print(f"⚠️  Key image duplicado (transação já processada): {key_image[:16]}...")
                return False
        
        # Specific validations by type
        if tx_type == 'USER_REGISTRATION':
            if 'public_key' not in transaction:
                return False
        
        elif tx_type == 'AUCTION_ANNOUNCE':
            data = transaction.get('data', {})
            required_fields = ['auction_id', 'item_description', 'start_time', 'end_time',  'reserve_price_commitment' , 'ring_signature', 'timestamp_signature', 'timestamp_hash']
            if not all(field in data for field in required_fields):
                missing = [field for field in required_fields if field not in data]
                print(f"Invalid auction - missing fields {missing}")
                return False
            if not self.verify_trusted_timestamp(transaction):
                print(f"Auction Announce rejected - invalid timestamp")
                return False
        
        elif tx_type == 'BID':
            data = transaction.get('data', {})
            required_fields = ['bid_id', 'auction_id', 'bid_value', 'ring_signature', 'timestamp_signature', 'timestamp_hash']
            if not all(field in data for field in required_fields):
                missing = [field for field in required_fields if field not in data]
                print(f"Invalid auction - missing fields {missing}")
                return False
            
            if not self.verify_trusted_timestamp(transaction):
                print(f"BID rejected - invalid timestamp")
                return False
        
        # Valid transaction - add to seen set
        self.seen_transaction_hashes.add(tx_hash)
        
        if tx_type in ['AUCTION_ANNOUNCE', 'BID']:
            data = transaction.get('data', {})
            ring_sig = data.get('ring_signature', {})
            key_image = ring_sig.get('key_image')
            if key_image:
                self.used_key_images.add(key_image)
        
        return True
    
    def add_transaction(self, transaction):
        """
        Add transaction to pending
        
        ✅ FIXED: Now validates before adding
        
        Args:
            transaction: Transaction to add
        """
        if self.validate_transaction(transaction):
            self.pending_transactions.append(transaction)
            return True
        else:
            print(f"⚠️  Invalid transaction rejected: {transaction.get('type', 'unknown')}")
            return False
        
    def add_block(self, block):
        """
        Add block to blockchain
        
        Args:
            block: Block to add
        """
        last_block = self.get_last_block()
        
        # Detailed debug
        if block.previous_hash != last_block.hash:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"❌ HASH CONFLICT:")
            logger.error(f"   Received block #{block.index}")
            logger.error(f"   Expected previous hash: {block.previous_hash[:16]}...")
            logger.error(f"   Local last block: #{last_block.index}")
            logger.error(f"   Last block hash: {last_block.hash[:16]}...")
            logger.error(f"   Chain length: {len(self.chain)}")
            raise ValueError("Previous hash does not match")
        
        if not block.verify_integrity():
            raise ValueError("Invalid block hash")
        
        for tx in block.transactions:
            tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
            self.seen_transaction_hashes.add(tx_hash)
        
        self.chain.append(block)
        
    def mine_pending_transactions(self):
        """
        Mine block with pending transactions
        
        Returns:
            Block: Mined block or None if no transactions
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
        Replace chain if new one is longer and valid (consensus)
        """
        if len(new_chain) > len(self.chain):
            if self.is_chain_valid(new_chain):
                self.chain = new_chain
                
                # Rebuild seen transactions set
                import json
                import hashlib
                self.seen_transaction_hashes.clear()
                for block in self.chain:
                    for tx in block.transactions:
                        tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                        self.seen_transaction_hashes.add(tx_hash)
                        if tx.get('type') in ['AUCTION_ANNOUNCE', 'BID']:
                            data = tx.get('data', {})
                            ring_sig = data.get('ring_signature', {})
                            key_image = ring_sig.get('key_image')
                            if key_image:
                                self.used_key_images.add(key_image)
                    
                return True
        return False
    
    def is_valid(self):
        """Verify local chain integrity"""
        return self.is_chain_valid(self.chain)
    
    def is_chain_valid(self, chain):
        """
        Validate a chain
        
        Args:
            chain: List of blocks to validate
            
        Returns:
            bool: True if valid, False otherwise
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
        """Save complete chain to disk"""
        import json
    
        chain_data = [block.to_dict() for block in self.chain]
    
        with open(filepath, 'w') as f:
            json.dump(chain_data, f, indent=2)

    def load_from_disk(self, filepath='blockchain.json'):
        """Load chain from disk"""
        import json
        from block import Block
        
        try:
            with open(filepath, 'r') as f:
                chain_data = json.load(f)
            
            self.chain = [Block.from_dict(block_dict) for block_dict in chain_data]
            
            # Rebuild seen transactions set
            self.seen_transaction_hashes.clear()
            for block in self.chain:
                for tx in block.transactions:
                    tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                    self.seen_transaction_hashes.add(tx_hash)
            self.used_key_images.clear()
            for block in self.chain:
                for tx in block.transactions:
                    if tx.get('type') in ['AUCTION_ANNOUNCE', 'BID']:
                        data = tx.get('data', {})
                        ring_sig = data.get('ring_signature', {})
                        key_image = ring_sig.get('key_image')
                        if key_image:
                            self.used_key_images.add(key_image)
                            
        except FileNotFoundError:
            print("File does not exist, using genesis block")
            self.chain = [self.create_genesis_block()]
    
    def get_transactions_by_type(self, t_type):
        """
        Search transactions by type
        
        Args:
            t_type: Transaction type ('BID', 'AUCTION_ANNOUNCE', etc)
            
        Returns:
            list: List of transactions of specified type
        """
        results = []
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('type') == t_type:
                    results.append(tx)
        return results
    
    def get_all_user_keys(self):
        """
        Extract public keys from registered users
        
        ✅ FIXED: Now also searches in pending_transactions!
        
        Returns:
            list: List of public keys
        """
        # Search in mined blocks
        user_reg_txs = self.get_transactions_by_type('USER_REGISTRATION')
        
        # ✅ ALSO search in pending transactions!
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