from block import Block
from crypto_utils import deserialize_key, verify_signature
import time
import json
import hashlib
import logging

logger = logging.getLogger(__name__)


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
        """Validate transaction before adding"""
        
        print(f"DEBUG validate_transaction: type={transaction.get('type')}, timestamp={transaction.get('timestamp')}")
    
        # Verify basic structure
        if not isinstance(transaction, dict):
            return False
        
        if 'type' not in transaction or 'timestamp' not in transaction:
            return False

        tx_hash = hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()
        
        if tx_hash in self.seen_transaction_hashes:
            return False
        
        # Verify timestamp (cannot be too far in the future)
        current_time = time.time()
        if transaction['timestamp'] > current_time + 300:  # 5 min tolerance
            return False
        
        tx_type = transaction.get('type')
        
        if tx_type in ['AUCTION_ANNOUNCE', 'BID']:
            data = transaction.get('data', {})
            ring_sig = data.get('ring_signature', {})
            key_image = ring_sig.get('key_image')
            
            if key_image and key_image in self.used_key_images:
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
                return False
            if not self.verify_trusted_timestamp(transaction):
                return False
        
        elif tx_type == 'BID':
            data = transaction.get('data', {})
            required_fields = ['bid_id', 'auction_id', 'bid_value', 'ring_signature', 'timestamp_signature', 'timestamp_hash']
            if not all(field in data for field in required_fields):
                missing = [field for field in required_fields if field not in data]
                return False
            
            if not self.verify_trusted_timestamp(transaction):
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
        """Add transaction to pending"""
        
        if self.validate_transaction(transaction):
            self.pending_transactions.append(transaction)
            return True
        else:
            print(f"⚠️  Invalid transaction rejected: {transaction.get('type', 'unknown')}")
            return False
        
    def add_block(self, block):
        """Add block to blockchain"""
        last_block = self.get_last_block()
        
        if not block.verify_integrity():
            raise ValueError("Invalid block hash")
        
        for tx in block.transactions:
            tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
            self.seen_transaction_hashes.add(tx_hash)
        
        self.chain.append(block)
        
    def mine_pending_transactions(self):
        """Mine block with pending transactions"""
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
        """Merge chains with conflict resolution"""
        
        local_len = len(self.chain)
        new_len = len(new_chain)
        
        # Validate new chain
        if not self.is_chain_valid(new_chain):
            logger.warning("Received invalid chain")
            return False
        
        # Find divergence point
        divergence_id = None
        min_len = min(local_len, new_len)
        
        for i in range(1, min_len):
            if self.chain[i].hash != new_chain[i].hash:
                divergence_id = i
                logger.info(f"Chains diverged at block #{divergence_id}")
                break
        
        # Case 1: No divergence - simple length comparison
        if divergence_id is None:
            if new_len > local_len:
                logger.info(f"Accepting longer chain ({new_len} vs {local_len})")
                self.chain = new_chain
                self._rebuild_transaction_sets()
                return True
            else:
                logger.info(f"Keeping local chain (same or longer)")
                return False
        
        # Case 2: Divergence detected - need to merge
        logger.info(f"Merging divergent chains (local: {local_len}, remote: {new_len})")
        
        # Decision criteria: accept longer chain as base, but preserve transactions
        if new_len > local_len:
            logger.info("Remote chain is longer - using as base for merge")
            base_chain = new_chain
            merge_blocks = self.chain[divergence_id:]
        elif new_len < local_len:
            logger.info("Local chain is longer - keeping as base for merge")
            # Just merge remote transactions into local
            merged_txs = self._merge_divergent_transactions(
                self.chain[divergence_id:],
                new_chain[divergence_id:]
            )
            if merged_txs:
                self._rebuild_from_divergence(divergence_id, merged_txs)
                logger.info(f"Merged {len(merged_txs)} transactions")
                return True
            return False
        else:
            # Same length - merge both
            logger.info("Chains same length - merging both branches")
            merged_txs = self._merge_divergent_transactions(
                self.chain[divergence_id:],
                new_chain[divergence_id:]
            )
            if merged_txs:
                self._rebuild_from_divergence(divergence_id, merged_txs)
                logger.info(f"Merged {len(merged_txs)} transactions")
                return True
            return False
    
    def _merge_divergent_transactions(self, local_blocks, remote_blocks):
        """Merge transactions from divergent blocks"""
        
        all_txs = []
        seen_hashes = set()
        seen_key_images = set()
        
        # Collect from local blocks
        for block in local_blocks:
            for tx in block.transactions:
                tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                
                # Check for duplicate hash
                if tx_hash in seen_hashes:
                    continue
                
                # Check for duplicate key image (double-spend protection)
                if tx.get('type') in ['AUCTION_ANNOUNCE', 'BID']:
                    data = tx.get('data', {})
                    ring_sig = data.get('ring_signature', {})
                    key_image = ring_sig.get('key_image')
                    
                    if key_image and key_image in seen_key_images:
                        logger.warning(f"Skipping duplicate key image from local: {tx.get('type')}")
                        continue
                    
                    if key_image:
                        seen_key_images.add(key_image)
                
                all_txs.append(tx)
                seen_hashes.add(tx_hash)
        
        # Collect from remote blocks
        for block in remote_blocks:
            for tx in block.transactions:
                tx_hash = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
                
                # Check for duplicate hash
                if tx_hash in seen_hashes:
                    continue
                
                # Check for duplicate key image (double-spend protection)
                if tx.get('type') in ['AUCTION_ANNOUNCE', 'BID']:
                    data = tx.get('data', {})
                    ring_sig = data.get('ring_signature', {})
                    key_image = ring_sig.get('key_image')
                    
                    if key_image and key_image in seen_key_images:
                        logger.warning(f"Skipping duplicate key image from remote: {tx.get('type')}")
                        continue
                    
                    if key_image:
                        seen_key_images.add(key_image)
                
                all_txs.append(tx)
                seen_hashes.add(tx_hash)
        
        # Sort by timestamp to maintain chronological order
        all_txs.sort(key=lambda tx: tx.get('timestamp', 0))
        
        logger.info(f"Merged {len(all_txs)} unique transactions from divergent branches")
        return all_txs
    
    def _rebuild_from_divergence(self, divergence_id, merged_txs):
        """Rebuild chain from divergence point"""
        
        self.chain = self.chain[:divergence_id]
        
        max_txs_per_block = 100
        for i in range(0, len(merged_txs), max_txs_per_block):
            chunk = merged_txs[i:i + max_txs_per_block]
            
            new_block = Block(
                index=len(self.chain),
                previous_hash=self.chain[-1].hash,
                timestamp=time.time(),
                transactions=chunk
            )
            new_block.mine_block(self.difficulty)
            self.chain.append(new_block)
        
        self._rebuild_transaction_sets()
    
    def _rebuild_transaction_sets(self):
        """Rebuild transaction tracker"""
        
        self.seen_transaction_hashes.clear()
        self.used_key_images.clear()
        
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
    
    def is_valid(self):
        """Verify local chain integrity"""
        return self.is_chain_valid(self.chain)
    
    def is_chain_valid(self, chain):
        """Validate a chain"""
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
        """Search transactions by type"""
        results = []
        for block in self.chain:
            for tx in block.transactions:
                if tx.get('type') == t_type:
                    results.append(tx)
        return results
    
    def get_all_user_keys(self):
        """Extract public keys from registered users"""
        # Search in mined blocks
        user_reg_txs = self.get_transactions_by_type('USER_REGISTRATION')
        
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