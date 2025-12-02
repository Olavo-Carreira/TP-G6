import socket
import requests
import time
import threading
import json
import logging
import hashlib

from blockchain import Blockchain
from network import start_p2p_server, connect_to_peer, send_message, broadcast_to_peers, receive_message
from crypto_utils import generate_keypair, serialize_key, deserialize_key, decryprt_from_dest, encrypt_for_dest
from manager import AuctionManager
from announcement import AuctionAnnouncement
from reveal import IdentityReveal
from bid import Bid
from commitement import save_secret_locally, load_secret_for_reveal, create_commitment
from cli import *
from status import AuctionStatus
from block import Block


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class AuctionNode:
    """P2P node to participate in anonymous auctions"""
    
    def __init__(self, username, server_url='http://localhost:5001', p2p_port=None):
        self.username = username
        self.server_url = server_url
        
        # Generate cryptographic keys
        self.private_key, self.public_key = generate_keypair()
        logger.info(f"Keys generated for {username}")
        
        # Local blockchain
        self.blockchain = Blockchain(server_public_key = None)
        
        # Auction Manager (complete integration!)
        self.auction_manager = AuctionManager(self.blockchain)
        
        # P2P networking
        self.p2p_port = p2p_port or self._find_free_port()
        self.peer_sockets = []
        
        # Ring keys cache
        self.ring_keys = []
        
        # Local secrets (reserve prices and bid nonces)
        self.my_secrets = {}  # {auction_id: {'reserve_nonce': ..., 'type': 'seller'}}
        
        self.processed_bid_ids = set()
        
        self.time_offset = 0 # Possible solution for the future issue in alice
        
        self.server_public_key = None
        
        # TIAGO
        self.my_won_auctions = set()  # {auction_id}
        
        logger.info(f"Node {username} created on port {self.p2p_port}")
    
    def _find_free_port(self):
        """Find free port automatically"""
        with socket.socket() as s:
            s.bind(('', 0))
            return s.getsockname()[1]
    
    def _listen_to_peer(self, peer_socket):
        """Thread to listen to messages from a peer"""
        try:
            while True:
                message = receive_message(peer_socket)
                if message is None:
                    logger.debug("Peer closed connection")
                    break
                self.handle_p2p_message(message, peer_socket)
        except Exception as e:
            logger.error(f"Error in listen thread: {e}")
        finally:
            try:
                peer_socket.close()
            except:
                pass
            if peer_socket in self.peer_sockets:
                self.peer_sockets.remove(peer_socket)
    
    # ==================== INITIALIZATION ====================
    
    def start(self):
        """Start complete node"""
        print_header(f"STARTING NODE {self.username}")
        
        # 1. Register with server
        print_info("Registering with central server...")
        self.register_with_server()
        
        print_info("Synchronizing clock")
        if self.sync_time_with_server():
            print_success(f"Clock synchronized")
        else:
            print("Could not synchronize clock")
            
        print_info("Getting server key")
        if self.get_server_public_key():
            print_success("Server key obtained")
        else:
            print_warning("No server key - timestamps not verifiable")
            
        # 2. Start P2P server
        print_info("Starting P2P server...")
        self.start_p2p_server()
        
        # 3. Announce presence
        print_info("Announcing presence...")
        self.announce_to_server()
        
        # 4. Discover and connect to peers
        print_info("Discovering peers...")
        self.discover_and_connect_peers()
        
        # 5. Synchronize blockchain
        print_info("Synchronizing blockchain...")
        self.sync_blockchain()
        
        # 6. Update ring keys
        print_info("Updating key ring...")
        self.update_ring_keys()

        print_success(f"Node {self.username} ready!")
        time.sleep(1)
    
    def register_with_server(self):
        """Register with central server"""
        try:
            pub_key_bytes = serialize_key(self.public_key, is_private=False)
            pub_key_str = pub_key_bytes.decode('utf-8')
            
            response = requests.post(f'{self.server_url}/register', json = {
                'username': self.username,
                'public_key' : pub_key_str
            })
            
            if response.status_code == 200:
                logger.info("Registered with central server")
            else:
                logger.warning("Registration failed: {response.text}")
                
            existing_txs = self.blockchain.get_transactions_by_type('USER_REGISTRATION')
            for tx in existing_txs:
                if tx.get('public_key') == pub_key_str:
                    logger.info(f"Already registered previously")
                    return
            
            if response.status_code == 200:
                # Add to blockchain
                self.blockchain.add_transaction({
                    'type': 'USER_REGISTRATION',
                    'public_key': pub_key_bytes.decode('utf-8'),
                    'timestamp': time.time()
                })
                logger.info("Registered with server")
            else:
                logger.warning(f"Registration failed: {response.text}")
        
        except Exception as e:
            logger.error(f"Error registering: {e}")
    
    def announce_to_server(self):
        """Announce presence to server"""
        try:
            response = requests.post(f'{self.server_url}/peers/announce', json={
                'peer_id': self.username,
                'port': self.p2p_port
            })
            
            if response.status_code == 200:
                logger.info("Presence announced")
        
        except Exception as e:
            logger.error(f"Error announcing: {e}")
    
    def get_peers_from_server(self):
        """Get peer list from server"""
        try:
            response = requests.get(f'{self.server_url}/peers/list')
            
            if response.status_code == 200:
                data = response.json()
                peers = data.get('peers', [])
                # Filter self
                peers = [p for p in peers if p.get('ip') != '127.0.0.1' or p.get('port') != self.p2p_port]
                return peers
        
        except Exception as e:
            logger.error(f"Error getting peers: {e}")
        
        return []
    
    def get_trusted_timestamp(self, data_hash):
        """Get trusted timestamp from server"""
        
        try:
            response = requests.post(f'{self.server_url}/timestamp', json = {
                'hash' : data_hash
            }, timeout = 5)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Timestamp server failed")
                return None
        
        except Exception as e:
            logger.error(f"Timestamp error: {e}")
            return None
    
    def get_trusted_time(self, data_for_hash=""):
        """Get only the timestamp"""
        
        data_hash = hashlib.sha256(data_for_hash.encode()).hexdigest()
        ts_data = self.get_trusted_timestamp(data_hash)
        
        if ts_data:
            return {
                'timestamp': ts_data['timestamp'],
                'signature': ts_data['signature'],
                'hash': data_hash
            }
        else:
            raise Exception("Timestamp server not available!")
        
    def sync_time_with_server(self):
        """Calculate time offset between server and local"""
        
        try:
            # RTT
            local_before = time.time()
            
            response = requests.get(f'{self.server_url}/health', timeout = 5)
            
            local_after = time.time()
            
            if response.status_code == 200:
                server_time = response.json().get('timestamp')
                
                rtt = local_after - local_before
                local_time = local_before + (rtt/2)
                
                self.time_offset = server_time - local_time
                
                if abs(self.time_offset) > 1: 
                    logger.warning(f"Clock desynchronized: {self.time_offset:.2f}s difference")
                else:
                    logger.info(f"Time synchronized (offset: {self.time_offset:.3f}s)")
                
                return True
            
        except Exception as e:
            logger.error(f"Error synchronizing time: {e}")
            self.time_offset = 0
        
        return False
    
    def get_server_public_key(self):
        """Get server public key to verify timestamps"""
        
        if self.server_public_key:
            return self.server_public_key
        
        try:
            response = requests.post(f'{self.server_url}/timestamp',
                                    json = {'hash': 'init'},
                                    timeout = 5)
            
            if response.status_code == 200:
                data = response.json()
                pubkey_str = data.get('server_pubkey')
                
                if pubkey_str:
                    self.server_public_key = deserialize_key(
                        pubkey_str.encode('utf-8'),
                        is_private = False
                    )
                    
                    self.blockchain.server_public_key = self.server_public_key
                    
                    logger.info("Server public key obtained")
                    return self.server_public_key
        
        except Exception as e:
            logger.error(f"Error getting server key: {e}")
            
        return None
    
    def get_server_time(self):
        """Time adjusted for server"""
        
        return time.time() + self.time_offset
    
    
    
    # ==================== P2P NETWORKING ====================
    
    def start_p2p_server(self):
        """Start P2P server"""
        start_p2p_server(self.p2p_port, self.handle_p2p_message)
        logger.info(f"P2P server on port {self.p2p_port}")
    
    def discover_and_connect_peers(self):
        """Discover and connect to peers"""
        peers = self.get_peers_from_server()
        logger.info(f"Discovered {len(peers)} peers")
        
        for peer in peers:
            peer_socket = connect_to_peer(peer['ip'], peer['port'])
            
            if peer_socket:
                self.peer_sockets.append(peer_socket)
                listener_thread = threading.Thread(
                    target=self._listen_to_peer,
                    args=(peer_socket,),
                    daemon=True
                )
                listener_thread.start()
    
    def handle_p2p_message(self, message, sender_socket):
        """
        Central handler for P2P messages
        
        ✅ COMPLETE: Handles all message types
        """
        # Add socket to list if new
        if sender_socket not in self.peer_sockets:
            self.peer_sockets.append(sender_socket)
        
        msg_type = message.get('type')
        logger.debug(f"Received: {msg_type}")
        
        try:
            if msg_type == 'ENCRYPTED_REVEAL':
                self.receive_encrypted_reveal(message)
                return
                
            if msg_type == 'REQUEST_BLOCKCHAIN':
                self.send_blockchain(sender_socket)
                return
            
            elif msg_type == 'BLOCKCHAIN':
                self.receive_blockchain(message)
                return
            
            elif msg_type == 'NEW_BLOCK':
                self.receive_new_block(message)
                return
            
            elif msg_type == 'AUCTION_ANNOUNCE':
                self.receive_auction_announcement(message)
                return
            
            elif msg_type == 'BID':
                self.receive_bid(message)
                return
            
            elif msg_type == 'AUCTION_RESULT':
                self.receive_auction_result(message)
                return
            
            elif msg_type == 'IDENTITY_REVEAL':
                self.receive_identity_reveal(message)
                return
            
            else:
                logger.warning(f"Unknown type: {msg_type}")
        
        except Exception as e:
            logger.error(f"Error processing message {msg_type}: {e}")
    
    # ==================== BLOCKCHAIN SYNC ====================
    
    def sync_blockchain(self):
        """Synchronize blockchain with peers"""
        if not self.peer_sockets:
            logger.info("No peers, using local blockchain")
            return
        
        request = {'type': 'REQUEST_BLOCKCHAIN'}
        send_message(self.peer_sockets[0], request)
    
    def send_blockchain(self, peer_socket):
        """Send blockchain to peer"""
        chain_data = [block.to_dict() for block in self.blockchain.chain]
        
        response = {
            'type': 'BLOCKCHAIN',
            'chain': chain_data
        }
        
        send_message(peer_socket, response)
    
    def receive_blockchain(self, message):
        """Receive blockchain from peer"""
        from block import Block
        
        chain_data = message.get('chain', [])
        received_chain = [Block.from_dict(b) for b in chain_data]
        
        if self.blockchain.replace_chain(received_chain):
            logger.info("Blockchain updated")
            # ✅ UPDATE RING after sync
            self.update_ring_keys()
            # Rebuild auction manager from blockchain
            self.rebuild_auction_manager_from_blockchain()
        else:
            logger.info("Local blockchain already up to date")
    
    def receive_new_block(self, message):
        """
        Receive new block from peer
        
        ✅ FIX: Removed duplicate processing - rebuild_auction_manager already processes everything
        """
        
        block_data = message.get('block')
        new_block = Block.from_dict(block_data)
        
        try:
            self.blockchain.add_block(new_block)
            logger.info(f"Block #{new_block.index} added")
            
            for tx in new_block.transactions:
                if tx.get('type') == 'auction_result':
                    auction_id = tx.get('data', {}).get('auction_id')
                    if auction_id:
                        self.check_if_i_won(auction_id)
            
            # ✅ UPDATE RING after receiving block (may have new registrations!)
            self.update_ring_keys()
            
            # ✅ REBUILD AUCTION MANAGER (already processes all transactions)
            self.rebuild_auction_manager_from_blockchain()
            
            
        
        except Exception as e:
            logger.warning(f"Block rejected: {e}")
    
    # ==================== AUCTION HANDLERS ====================
    
    def receive_auction_announcement(self, message):
        """Receive auction announcement"""
        try:
            data = message.get('data')
            announcement = AuctionAnnouncement.from_dict(data)
            
            print(f"🔍 DEBUG: Announcement received - ID: {announcement.auction_id}")
            print(f"🔍 DEBUG: Available ring keys: {len(self.ring_keys)}")
            
            # Verify validity
            if self.auction_manager.verify_auction_announcement(announcement):
                # Add to manager
                self.auction_manager.auctions[announcement.auction_id] = announcement
                self.auction_manager.bids[announcement.auction_id] = []
            
            

                current_time = time.time()
                if current_time < announcement.start_time:
                    status = AuctionStatus.ANNOUNCED
                elif current_time <= announcement.end_time:
                    status = AuctionStatus.ACTIVE
                else:
                    status = AuctionStatus.BIDDING_CLOSED
                
                self.auction_manager.auction_status[announcement.auction_id] = status
                
                print_info(f"New auction: {announcement.item_description} ({announcement.auction_id})")
                
                self.blockchain.add_transaction({
                    'type': 'AUCTION_ANNOUNCE',
                    'data': announcement.to_dict(),
                    'timestamp': announcement.timestamp
                })
                
                logger.debug(f"🔍 DEBUG: ANNOUNCEMENT added to local pool")
                logger.debug(f"   Pool size now: {len(self.blockchain.pending_transactions)}")
                logger.debug(f"   Auction ID: {announcement.auction_id}")
            else:
                logger.warning("Invalid announcement received")
        
        except Exception as e:
            logger.error(f"Error processing announcement: {e}")
    
    def receive_bid(self, message):
        """Receive bid"""
        try:
            data = message.get('data')
            bid = Bid.from_dict(data)
            
            if bid.bid_id in self.processed_bid_ids:
                return
            
            if self.auction_manager.verify_bid(bid):
                if bid.auction_id not in self.auction_manager.bids:
                    self.auction_manager.bids[bid.auction_id] = []
                
                self.auction_manager.bids[bid.auction_id].append(bid)
                
                self.processed_bid_ids.add(bid.bid_id)
                
                print_info(f"New bid of {bid.bid_value:.2f}€ in auction {bid.auction_id}")
                
                self.blockchain.add_transaction({
                    'type': 'BID',
                    'data': bid.to_dict(),
                    'timestamp': bid.timestamp
                })
                
                logger.debug(f"🔍 DEBUG: BID added to local pool")
                logger.debug(f"   Pool size now: {len(self.blockchain.pending_transactions)}")
                logger.debug(f"   Bid ID: {bid.bid_id}")
            else:
                logger.warning("Invalid bid received")
                        
        except Exception as e:
            logger.error(f"Error processing bid: {e}")
    
    def receive_auction_result(self, message):
        """Receive auction result"""
        
        print(f"🔍 DEBUG: receive_auction_result called")
        print(f"🔍 DEBUG: Message data: {message.get('data', {}).get('auction_id')}")
    
        try:
            data = message.get('data')
            auction_id = data.get('auction_id')
            
            if auction_id in self.auction_manager.auction_status:
                self.auction_manager.auction_status[auction_id] = AuctionStatus.COMPLETED
            
            if data.get('has_winner'):
                print_success(f"Auction {auction_id} has winner! Value: {data.get('winning_amount')}€")
                
                winning_commitment = data.get('winner_bid_commitment')
                
                my_bids_for_auction = []
                
                for key, secret in self.my_secrets.items():
                    if key.startswith('bid_') and secret.get('auction_id') == auction_id:
                        my_bids_for_auction.append(secret)
                        
                for secret in my_bids_for_auction:
                    bid_value = secret['bid_value']
                    bid_nonce = secret['bid_nonce']
                    
                    data_str = f"{auction_id}:{bid_value}:{bid_nonce}"
                    my_commitment = hashlib.sha256(data_str.encode('utf-8')).hexdigest()
                    
                    print(f"DEBUG: Comparing commits")
                    print(f"Winning: {winning_commitment}")
                    print(f"Mine: {my_commitment}")
                    
                    if my_commitment == winning_commitment:
                        print_success("You won the auction")
                        
                        winner_reveal = self.auction_manager.winner_reveal_identity(
                            auction_id = auction_id,
                            winner_public_key = self.public_key,
                            winning_bid_commitment = winning_commitment
                        )
                        
                        broadcast_to_peers(self.peer_sockets, {
                            'type': 'IDENTITY_REVEAL',
                            'data': winner_reveal.to_dict()
                        })
                        
                        print_info("Identity revealed. Waiting for seller...")
                        break
            else:
                print_info(f"Auction {auction_id} closed without winner")
        
        except Exception as e:
            logger.error(f"Error processing result: {e}")
    
    def receive_identity_reveal(self, message):
        """Receive identity reveal"""
        try:
            
            data = message.get('data')
            reveal = IdentityReveal.from_dict(data)
            auction_id = reveal.auction_id
            role = reveal.role
            
            # ✅ DEBUG
            print(f"DEBUG: Received IDENTITY_REVEAL - role={role}, auction_id={auction_id}")
            print(f"DEBUG: My username={self.username}")
            
            # Store in identity_manager
            if reveal.role == "seller":
                self.auction_manager.identity_manager.identity_reveals.setdefault(auction_id, {})
                self.auction_manager.identity_manager.identity_reveals[auction_id]["seller"] = reveal
                print_info(f"Seller revealed identity in auction {auction_id}")
            
            elif reveal.role == "winner":
                self.auction_manager.identity_manager.identity_reveals.setdefault(auction_id, {})
                self.auction_manager.identity_manager.identity_reveals[auction_id]["winner"] = reveal
                print_info(f"Winner revealed identity in auction {auction_id}")
            
            # ✅ DEBUG
            reveals = self.auction_manager.identity_manager.identity_reveals.get(auction_id, {})
            print(f"DEBUG: Reveals stored for {auction_id}: {list(reveals.keys())}")
            
            # ✅ CHECK IF BOTH REVEALED
            if self.auction_manager.identity_manager.are_identities_revealed(auction_id):
                print(f"DEBUG: BOTH REVEALED! Going to show info...")
                
                seller_reveal = self.auction_manager.identity_manager.get_seller_identity(auction_id)
                winner_reveal = self.auction_manager.identity_manager.get_winner_identity(auction_id)
                
                seller_username = self._get_username_from_pubkey(seller_reveal.public_key)
                winner_username = self._get_username_from_pubkey(winner_reveal.public_key)
                
                # Check if I AM the seller or winner of this auction
                my_pubkey_str = serialize_key(self.public_key, is_private=False).decode('utf-8')
                
                if seller_reveal.public_key == my_pubkey_str or winner_reveal.public_key == my_pubkey_str:
                    print("\n" + "="*60)
                    print_success("🎉 IDENTITIES REVEALED - AUCTION INFORMATION")
                    print("="*60)
                    print(f"   🏛️  Auction ID: {auction_id}")
                    print(f"   👤 Seller: {seller_username}")
                    print(f"   🏆 Winner: {winner_username}")
                    print("="*60 + "\n")
            else:
                print(f"DEBUG: Still missing reveals. Stored: {list(reveals.keys())}")
        
        except Exception as e:
            logger.error(f"Error processing reveal: {e}")
            import traceback
            traceback.print_exc()
    
    def receive_encrypted_reveal(self, message):
        """Receive reveal and try to decrypt"""
        
        try:
            required = ['encrypted_key', 'encrypted_data', 'tag', 'nonce']
            if not all(field in message for field in required):
                logger.debug("Encrypted_Reveal with missing fields")
                return
            
            decrypted = decryprt_from_dest(message, self.private_key)
            
            if decrypted is None:
                logger.debug("Encrypted_Reveal not for me")
                return
            
            logger.info("Received private identity reveal")
            
            reveal = IdentityReveal.from_dict(decrypted)
            auction_id = reveal.auction_id
            
            if auction_id not in self.auction_manager.identity_manager.identity_reveals:
                self.auction_manager.identity_manager.identity_reveals[auction_id] = {}
                
            if reveal.role == "seller":
                self.auction_manager.identity_manager.identity_reveals[auction_id]["seller"] = reveal
                print_success(f"Seller revealed identity")
                logger.info(f"Auction: {auction_id}")
                
            elif reveal.role == "winner":
                self.auction_manager.identity_manager.identity_reveals[auction_id]["winner"] = reveal
                print_success(f"Winner revealed identity")
                logger.info(f"Auction: {auction_id}")

            if self.auction_manager.identity_manager.are_identities_revealed(auction_id):
                self._show_complete_auction_info(auction_id)
        
        except Exception as e:
            logger.error(f"Error processing encrypted reveal: {e}")
    
    def _show_complete_auction_info(self, auction_id):
        """Show complete information when identities are revealed"""
        
        seller_reveal = self.auction_manager.identity_manager.get_seller_identity(auction_id)
        winner_reveal = self.auction_manager.identity_manager.get_winner_identity(auction_id)
        
        if not seller_reveal or not winner_reveal:
            return
        
        seller_username = self._get_username_from_pubkey(seller_reveal.public_key)
        winner_username = self._get_username_from_pubkey(winner_reveal.public_key)
        
        print("\n" + "="*70)
        print_success("🎉 AUCTION COMPLETED - BOTH IDENTITIES REVEALED")
        print("="*70)
        print(f"   🏛️  Auction ID: {auction_id}")
        print(f"   👤 Seller: {seller_username}")
        print(f"   🏆 Winner: {winner_username}")
        print("="*70)
        print("="*70 + "\n")
    
    def process_transaction(self, tx):
        """
        Process transaction added to blockchain
        
        ⚠️  DEPRECATED: Use rebuild_auction_manager_from_blockchain() instead
        """
        tx_type = tx.get('type')
        
        if tx_type == 'AUCTION_ANNOUNCE':
            self.receive_auction_announcement(tx)
        elif tx_type == 'BID':
            self.receive_bid(tx)
    
    def rebuild_auction_manager_from_blockchain(self):
        """
        Rebuild auction manager from blockchain
        
        Process all auctions and bids from blockchain to rebuild
        auction manager state after synchronization.
        
        ✅ This method already processes all transactions, avoiding duplication
        """
        logger.info("Rebuilding auction manager from blockchain...")
        
        # Process all blocks
        for block in self.blockchain.chain:
            for tx in block.transactions:
                tx_type = tx.get('type')
                
                if tx_type == 'AUCTION_ANNOUNCE':
                    try:
                        data = tx.get('data', {}).copy()
                        
                        if 'timestamp' not in data:
                            if 'timestamp' not in tx:
                                continue
                            data['timestamp'] = tx['timestamp']
                            
                        announcement = AuctionAnnouncement.from_dict(data)
                        
                        # Add to manager without verifying (already in blockchain)
                        self.auction_manager.auctions[announcement.auction_id] = announcement
                        if announcement.auction_id not in self.auction_manager.bids:
                            self.auction_manager.bids[announcement.auction_id] = []
                        
                        # Determine status based on timestamps
                        current_time = time.time()
                        if current_time < announcement.start_time:
                            from status import AuctionStatus
                            self.auction_manager.auction_status[announcement.auction_id] = AuctionStatus.ANNOUNCED
                        elif current_time <= announcement.end_time:
                            from status import AuctionStatus
                            self.auction_manager.auction_status[announcement.auction_id] = AuctionStatus.ACTIVE
                        else:
                            from status import AuctionStatus
                            self.auction_manager.auction_status[announcement.auction_id] = AuctionStatus.BIDDING_CLOSED
                        
                        logger.debug(f"Auction rebuilt: {announcement.auction_id}")
                    
                    except Exception as e:
                        logger.error(f"Error rebuilding auction: {e}")
                
                elif tx_type == 'BID':
                    try:
                        data = tx.get('data', {}).copy()
                        
                        if 'timestamp' not in data:
                            if 'timestamp' not in tx:
                                continue
                            data['timestamp'] = tx['timestamp']
                        bid = Bid.from_dict(data)
                        
                        if bid.bid_id in self.processed_bid_ids:
                            continue
                        
                        if bid.auction_id not in self.auction_manager.bids:
                            self.auction_manager.bids[bid.auction_id] = []
                            
                        self.auction_manager.bids[bid.auction_id].append(bid)
                        
                        self.processed_bid_ids.add(bid.bid_id)
                    
                    except Exception as e:
                        logger.error(f"Error rebuilding bid: {e}")
        
        logger.info(f"Rebuild complete: {len(self.auction_manager.auctions)} auctions")
    
    # ==================== AUCTION OPERATIONS ====================
    
    def create_auction(self, item_description, reserve_price, duration_minutes):
        """Create new auction"""
        
        try:
            print_progress("Creating auction...", 1)
            
            try:
                trusted_time_data = self.get_trusted_time(f"{self.username}{item_description}{reserve_price}")
            except Exception as e:
                print_error(f"Failed to get timestamp: {e}")
                print_warning("Cannot create auction without trusted timestamp")
                return None
            
            ring_keys_to_use = self.get_ring_keys_for_signing()
            
            announcement, reserve_nonce = self.auction_manager.create_auction_announcement(
                seller_private_key=self.private_key,
                item_description=item_description,
                reserve_price=reserve_price,
                duration_seconds=duration_minutes * 60,
                ring_public_keys=ring_keys_to_use,
                start_timestamp = trusted_time_data['timestamp'],
                timestamp_signature = trusted_time_data['signature'],
                timestamp_hash = trusted_time_data['hash']
            )
            
            # Save reserve nonce locally
            self.my_secrets[announcement.auction_id] = {
                'reserve_nonce': reserve_nonce,
                'reserve_price': reserve_price,
                'type': 'seller'
            }
            save_secret_locally({
                'auction_id': announcement.auction_id,
                'reserve_nonce': reserve_nonce,
                'reserve_price': reserve_price,
                'type': 'seller'
            })
            
            # Broadcast to peers
            message = {
                'type': 'AUCTION_ANNOUNCE',
                'data': announcement.to_dict(),
                'timestamp': announcement.timestamp
            }
            
            self.blockchain.add_transaction({
                'type': 'AUCTION_ANNOUNCE',
                'data': announcement.to_dict(),
                'timestamp': announcement.timestamp
            })
            broadcast_to_peers(self.peer_sockets, message)
            
            # Mine block
            self.mine_block()
            
            print_success(f"Auction created! ID: {announcement.auction_id}")
            
            return announcement.auction_id
        
        except Exception as e:
            print_error(f"Error creating auction: {e}")
            return None
    
    def submit_bid(self, auction_id, bid_amount):
        """Submit bid to auction"""
        
        try:
            
            if auction_id in self.my_secrets and self.my_secrets[auction_id].get('type') == 'seller':
                print_error("Cannot bid on your own auction")
                return False
            
            auction = self.auction_manager.get_auction(auction_id)
            if not auction:
                print_error("Auction not found")
                return False
            
            existing_bids = self.auction_manager.get_auction_bids(auction_id)
            if existing_bids:
                max_bid = max(existing_bids, key = lambda b: b.bid_value)
                if bid_amount <= max_bid.bid_value:
                    print_error(f"Bid lower than current winner")
                    return False
            
            print_progress("Submitting bid...", 1)
            
            try:
                trusted_time_data = self.get_trusted_time(f"{auction_id}{bid_amount}{self.username}")
            except Exception as e:
                print_error(f"Failed to get timestamp: {e}")
                print_warning("Cannot submit bid without trusted timestamp")
                return False
            
            ring_keys_to_use = self.get_ring_keys_for_signing()
            
            bid = self.auction_manager.submit_bid(
                auction_id=auction_id,
                bidder_private_key=self.private_key,
                bid_amount=bid_amount,
                ring_public_keys=ring_keys_to_use,
                bid_timestamp = trusted_time_data['timestamp'],
                timestamp_signature = trusted_time_data['signature'],
                timestamp_hash = trusted_time_data['hash']
            )
            
            # Save bid nonce locally
            self.my_secrets[f"bid_{bid.bid_id}"] = {
                'bid_nonce': bid.bid_nonce,
                'bid_value': bid_amount,
                'bid_commitment': bid.bid_commitment,
                'auction_id': auction_id,
                'type': 'bidder'
            }
            self.processed_bid_ids.add(bid.bid_id)
            
            save_secret_locally({
                'bid_id': bid.bid_id,
                'bid_nonce': bid.bid_nonce,
                'bid_value': bid_amount,
                'bid_commitment': bid.bid_commitment,
                'auction_id': auction_id,
                'type': 'bidder'
            })
            
            # Broadcast to peers
            message = {
                'type': 'BID',
                'data': bid.to_dict()
            }
            broadcast_to_peers(self.peer_sockets, message)
            
            # Mine block
            self.mine_block()
            
            print_success(f"Bid submitted! Value: {bid_amount}€")
            
            return True
        
        except Exception as e:
            print_error(f"Error submitting bid: {e}")
            return False
    
    def check_if_i_won(self, auction_id):
        """Check if I won an auction"""
        
        try:
            result_data = None
            
            for block in reversed(self.blockchain.chain):
                for tx in block.transactions:
                    if tx.get('type') == 'auction_result':
                        data = tx.get('data', {})
                        if data.get('auction_id') == auction_id:
                            result_data = data
                            break
                if result_data:
                    break
            
            if not result_data or not result_data.get('has_winner'):
                return False
            
            winner_commitment = result_data.get('winner_bid_commitment')
            
            for secret_key, secret_data in self.my_secrets.items():
                if (secret_data.get('type') == 'bidder' and
                    secret_data.get('auction_id') == auction_id and
                    secret_data.get('bid_commitment') == winner_commitment):
                    
                    # TIAGO
                    self.my_won_auctions.add(auction_id)
                    
                    print("\n" + "="*70)
                    print_success("🏆🏆🏆 CONGRATULATIONS! YOU WON THE AUCTION! 🏆🏆🏆")
                    print("="*70)
                    print(f"   🏛️  Auction ID: {auction_id}")
                    print(f"   💰 Your winning bid: {secret_data['bid_value']}€")
                    print(f"   🔒 Commitment: {winner_commitment[:16]}...")
                    print("="*70)
                    print("   📨 Revealing your identity to seller...")
                    print("="*70 + "\n")
                    
                    self._reveal_as_winner(auction_id, winner_commitment)
                    
                    return True
            return False
        except Exception as e:
            logger.error(f"Error checking winner: {e}")
            return False
        
    def _reveal_as_winner(self, auction_id, winning_commitment):
        """Reveal identity as winner"""
        
        try:
            print_progress("Revealing your identity", 1)
            print("🔍 DEBUG: Creating reveal...")
            reveal = self.auction_manager.identity_manager.reveal_winner_identity(
                auction_id = auction_id,
                winner_public_key = self.public_key,
                winning_bid_commitment = winning_commitment
            )
            print("✅ DEBUG: Reveal created")
            print(f"\n🔍 DEBUG: Available ring keys: {len(self.ring_keys)}")
            
            sent_count = 0
            
            for i, ring_key in enumerate(self.ring_keys):
                print(f"🔍 DEBUG: Trying to encrypt for key {i+1}/{len(self.ring_keys)}...")
                try:
                    encrypted_msg = reveal.to_encrypted_message(ring_key)
                    print(f"✅ DEBUG: Encryption {i+1} successful")
                    
                    broadcast_to_peers(self.peer_sockets, encrypted_msg)
                    sent_count += 1
                
                except Exception as e:
                    print(f"❌ DEBUG: Encryption {i+1} FAILED: {e}")
                    continue
            
            print()
            print_success(f"✅ Identity revealed!")
            print_info(f"   📤 Encrypted messages sent: {sent_count}")
            print_info(f"   🔐 Only seller can decrypt and see who you are")
            print()
        
        except Exception as e:
            logger.error(f"Error revealing as winner: {e}")
        
    def close_and_finalize_auction(self, auction_id):
        """
        Close and finalize auction (seller only)
        
        Args:
            auction_id: Auction ID
            
        Returns:
            bool: True if success
        """
        try:
            if auction_id not in self.my_secrets:
                return
            
            secret = self.my_secrets[auction_id]
            if secret.get('type') != 'seller':
                return
            
            auction = self.auction_manager.get_auction(auction_id)
            if not auction:
                return
            
            server_time = self.get_server_time()
            
            if server_time < auction.end_time:
                print_warning(f"Auction still active! Ends at {format_timestamp(auction.end_time)}")
                if not get_confirmation("Close anyway?"):
                    return

            print_progress("Closing bidding...", 1)
            
            self.auction_manager.close_bidding(auction_id, current_time=server_time)
            
            print_progress("Determining winner....", 1)
            
            result = self.auction_manager.finalize_auction(
                auction_id = auction_id,
                reserve_price = secret['reserve_price'],
                reserve_nonce = secret['reserve_nonce']
            )
            
            self.mine_block()
            print()
            
            if result.has_winner:
                print_info(f"Winner bid commitment: {result.winner_bid_commitment[:16]}")
                print_info(f"Winning amount: {result.winning_amount}€")
                print_info(f"Total valid bids: {result.total_valid_bids}")
                print()
            
                print_progress("Revealing your identity", 1)
            
                reveal = self.auction_manager.identity_manager.reveal_seller_identity(
                    auction_id = auction_id,
                    seller_public_key = self.public_key 
                )
                
                sent_count = 0
                failed_count = 0
                
                for i, ring_key in enumerate(self.ring_keys):
                    print(f"🔍 DEBUG: Trying to encrypt for key {i+1}/{len(self.ring_keys)}...")
                    try:
                        
                        encrypted_msg = reveal.to_encrypted_message(ring_key)
                        print(f"✅ DEBUG: Encryption {i+1} successful")
                        broadcast_to_peers(self.peer_sockets, encrypted_msg)
                        sent_count += 1
                    
                    except Exception as e:
                        print(f"❌ DEBUG: Encryption {i+1} FAILED: {e}")
                        failed_count += 1
                        continue
            
                print()
                print_success(f"✅ Identity revealed!")
                print_info(f"   📤 Encrypted messages sent: {sent_count}")
                print_info(f"   🔐 Only winner can decrypt and see who you are")
                print_info(f"   ⏳ Waiting for winner reveal...")
                
                if failed_count > 0:
                    logger.debug(f"   ⚠️  {failed_count} ring keys failed encryption")
            
            else:
                print_warning("❌ No winner")
                print_info(f"   Reserve price: {secret['reserve_price']}€")
                print_info(f"   No bid reached reserve price")
        
        except Exception as e:
            print_error(f"Error closing auction: {e}")
            
    def get_active_auctions(self):
        """Get list of active auctions"""
        
        server_time = self.get_server_time()
        
        return self.auction_manager.get_active_auctions(current_time=server_time)
    
    def get_auction_bids(self, auction_id):
        """Get bids from auction"""
        return self.auction_manager.get_auction_bids(auction_id)
    

    
    # ==================== MINING ====================
    
    def mine_block(self):
        """Mine block with pending transactions"""
        
        logger.debug(f"🔍 DEBUG MINE: Pool has {len(self.blockchain.pending_transactions)} transactions")
        for tx in self.blockchain.pending_transactions:
            logger.debug(f"   - {tx.get('type')}")

        if not self.blockchain.pending_transactions:
            logger.debug("No pending transactions to mine")
            return None
        
        logger.info(f"Mining block with {len(self.blockchain.pending_transactions)} transactions")
        logger.debug(f"Previous hash: {self.blockchain.get_last_block_hash()[:16]}...")
        logger.debug(f"Chain length before: {len(self.blockchain.chain)}")
        
        new_block = self.blockchain.mine_pending_transactions()
        
        if new_block:
            logger.info(f"Block #{new_block.index} mined!")
            logger.debug(f"New hash: {new_block.hash[:16]}...")
            logger.debug(f"Chain length after: {len(self.blockchain.chain)}")
            
            # Broadcast to peers
            message = {
                'type': 'NEW_BLOCK',
                'block': new_block.to_dict()
            }
            broadcast_to_peers(self.peer_sockets, message)
            logger.debug(f"Block sent to {len(self.peer_sockets)} peers")
        
        return new_block
    
    # ==================== UTILITIES ====================
    
    def update_ring_keys(self):
        """Update ring keys list from blockchain"""
        try:
            # ✅ ALWAYS ADD OWN KEY FIRST!
            self.ring_keys = [self.public_key]
            
            # Get all registered public keys from blockchain
            blockchain_keys = self.blockchain.get_all_user_keys()
            
            # Add blockchain keys (avoiding duplication)
            self_key_bytes = serialize_key(self.public_key, is_private=False)
            seen_keys = {self_key_bytes}
            
            for key in blockchain_keys:
                key_bytes = serialize_key(key, is_private=False)
                if key_bytes not in seen_keys:  
                    self.ring_keys.append(key)
                    seen_keys.add(key_bytes)
            
            logger.info(f"Ring updated: {len(self.ring_keys)} keys (including own)")
        
        except Exception as e:
            logger.error(f"Error updating ring keys: {e}")
    
    def get_node_info(self):
        """Get node information"""
        return {
            'username': self.username,
            'peers': self.get_active_peers_count(),
            'ring_keys': len(self.ring_keys),
            'blocks': len(self.blockchain.chain),
            'pending_txs': len(self.blockchain.pending_transactions),
            'active_auctions': len(self.get_active_auctions()),
            'ring_size': len(self.ring_keys)
        }
    
    def get_ring_keys_for_signing(self):
        """
        Get ring keys for signing (generates dummy keys if needed)
        
        Ring signatures need at least 3 keys.
        If not enough keys, generates dummy keys.
        
        Returns:
            list: List of serialized public keys
        """
        # Serialize all ring keys (already includes own key!)
        existing_keys = [serialize_key(key, is_private=False) for key in self.ring_keys]
        
        # If we have less than 3 keys, generate dummies
        MIN_RING_SIZE = 3
        while len(existing_keys) < MIN_RING_SIZE:
            dummy_priv, dummy_pub = generate_keypair()
            dummy_pub_bytes = serialize_key(dummy_pub, is_private=False)
            existing_keys.append(dummy_pub_bytes)
            logger.warning(f"⚠️  Generated dummy key for ring (total: {len(existing_keys)}) - Ring too small!")
        
        logger.debug(f"Ring for signing: {len(existing_keys)} keys")
        return existing_keys

    def _get_username_from_pubkey(self, public_key_str):
        """Find username through public key"""
        
        try:
            response = requests.post(
                f'{self.server_url}/lookup_username',
                json = {'public_key': public_key_str},
                timeout = 2
            )
            
            if response.status_code == 200:
                username = response.json().get('username')
                if username:
                    return username
                
        except Exception as e:
            logger.debug(f"Error getting username: {e}")
        
        return f"User-{public_key_str[:16]}..."
    
    def _get_pubkey_from_username(self, username):
        try:
            
            response = requests.post(
                f'{self.server_url}/lookup_pubkey',
                json = {'username':username},
                timeout = 2
            )
            
            if response.status_code == 200:
                pubkey_str = response.json().get('public_key')
                if pubkey_str:
                    return deserialize_key(pubkey_str.encode(), is_private = False)
                
        except Exception as e:
            logger.debug(f"Error getting pubkey: {e}")
        
        return None
        
    def get_active_peers_count(self):
        """Count only peers with active sockets"""
        
        active_sockets = []
        for sock in self.peer_sockets:
            try:
                sock.getpeername()
                active_sockets.append(sock)
            except:
                pass
        
        self.peer_sockets = active_sockets
        
        return len(self.peer_sockets)
    
    def cleanup_dead_sockets(self):
        """Remove dead sockets from peer list"""
        
        active_sockets = []
        removed_count = 0
        
        for sock in self.peer_sockets:
            try:
                sock.getpeername()
                active_sockets.append(sock)
            except:
                removed_count += 1
                try:
                    sock.close()
                except:
                    pass
        
        self.peer_sockets = active_sockets
        
        if removed_count > 0:
            logger.info(f"Removed {removed_count} dead sockets")


# ========== CLI MENU ====================

def run_cli(node):
    """
    Executar interface de linha de comandos
    
    Args:
        node: Instância de AuctionNode
    """
    while True:
        try:
            # Limpar ecrã e mostrar status
            clear_screen()
            
            node.cleanup_dead_sockets()
            
            print_logo()
            print_node_status(node)
            
            # Menu principal
            options = [
                "📢 Create Auction",
                "💰 Submit Bid",
                "📋 View Active Auctions",
                "🏆 My Auctions (Seller)",
                "🎖️  Won Auctions (Winner)",
                "🔓 Close Auction",
                "⛏️  Mine Block",
                "🔗 View Blockchain",
                "👥 View Peers",
                "🔄 Refresh",
                "❌ Exit"
            ]
            
            print_menu("MAIN MENU", options, width=60)
            
            print()
            choice = get_input("Choose an option", int, lambda x: 1 <= x <= len(options))
            
            if choice == 1:
                cli_create_auction(node)
            elif choice == 2:
                cli_submit_bid(node)
            elif choice == 3:
                cli_view_active_auctions(node)
            elif choice == 4:
                cli_view_my_auctions(node)
            elif choice == 5:
                cli_view_won_auctions(node)  
            elif choice == 6:
                cli_close_auction(node)
            elif choice == 7:
                cli_mine_block(node)
            elif choice == 8:
                cli_view_blockchain(node)
            elif choice == 9:
                cli_view_peers(node)
            elif choice == 10:
                continue  # Apenas refresh
            elif choice == 11:
                if get_confirmation("Are you sure you want to exit?"):
                    print_info("Closing node...")
                    break
        
        except KeyboardInterrupt:
            print("\n")
            if get_confirmation("Are you sure you want to exit?"):
                break
        except Exception as e:
            print_error(f"Error: {e}")
            press_enter_to_continue()


# ========== CLI FUNCTIONS ====================

def cli_create_auction(node):
    """CLI: Create auction"""
    clear_screen()
    print_header("CREATE AUCTION")
    
    item = get_input("Item description", str)
    reserve_price = get_input("Reserve price (€)", float, lambda x: x > 0)
    duration = get_input("Duration (minutes)", int, lambda x: x > 0)
    
    if get_confirmation("Confirm auction creation?"):
        auction_id = node.create_auction(item, reserve_price, duration)
        if auction_id:
            print_success(f"Auction created successfully!")
            print_info(f"ID: {auction_id}")
    
    press_enter_to_continue()


def cli_submit_bid(node):
    """CLI: Submit bid"""
    clear_screen()
    print_header("SUBMIT BID")
    
    # Show active auctions
    auctions = node.get_active_auctions()
    if not auctions:
        print_warning("No active auctions at the moment")
        press_enter_to_continue()
        return
    
    print("\nActive Auctions:")
    for i, auction in enumerate(auctions, 1):
        print(f"\n{i}. {auction.item_description}")
        print(f"   ID: {auction.auction_id}")
        print(f"   Ends: {format_timestamp(auction.end_time)}")
    
    idx = get_input(f"Choose auction (1-{len(auctions)})", int, lambda x: 1 <= x <= len(auctions))
    auction = auctions[idx - 1]
    
    while True:
        bids = node.get_auction_bids(auction.auction_id)
        if bids:
            max_bid = max(bids, key = lambda b: b.bid_value)
            print(f"\n Current highest bid: {max_bid.bid_value:.2f}€")
            print(f"Total bids: {len(bids)}")
        else:
            print("\n No bids yet in this auction")
        
        bid_amount = get_input("\n Your bid amount (€) [0 to cancel]", float, lambda x: x >= 0)
        
        if bid_amount == 0:
            print_info("Bid cancelled")
            break
        
        if get_confirmation(f"Confirm bid of {bid_amount:.2f}€?"):
            success = node.submit_bid(auction.auction_id, bid_amount)
            
            if not success:
                if not get_confirmation("Try with another value?"):
                    break
            else:
                break
        else:
            if not get_confirmation("Try with another value?"):
                break
    
    press_enter_to_continue()
            


def cli_view_active_auctions(node):
    """CLI: View active auctions"""
    clear_screen()
    print_header("ACTIVE AUCTIONS")
    
    auctions = node.get_active_auctions()
    server_time = node.get_server_time()
    
    if not auctions:
        print_warning("No active auctions at the moment")
    else:
        for auction in auctions:
            status = node.auction_manager.get_auction_status(auction.auction_id, current_time = server_time)
            print_auction_details(auction, status)
            
            # Show bids
            bids = node.get_auction_bids(auction.auction_id)
            if bids:
                print(f"\n  Bids ({len(bids)}):")
                for bid in sorted(bids, key=lambda b: b.bid_value, reverse=True):
                    print_bid_details(bid)
            print()
    
    press_enter_to_continue()


def cli_view_my_auctions(node):
    """CLI: View my auctions (seller)"""
    clear_screen()
    print_header("MY AUCTIONS")
    
    my_auctions = [aid for aid, secret in node.my_secrets.items() 
                if secret.get('type') == 'seller']
    
    if not my_auctions:
        print_warning("You haven't created any auctions yet")
    else:
        server_time = node.get_server_time()
        
        for auction_id in my_auctions:
            auction = node.auction_manager.get_auction(auction_id)
            if auction:
                status = node.auction_manager.get_auction_status(auction_id, current_time = server_time)
                print_auction_details(auction, status)
                
                bids = node.get_auction_bids(auction_id)
                print(f"  Total bids: {len(bids)}")
                if bids:
                    max_bid = max(bids, key=lambda b: b.bid_value)
                    print(f"  Highest bid: {max_bid.bid_value:.2f}€")
                print()
    
    press_enter_to_continue()


def cli_view_won_auctions(node):
    """CLI: View won auctions (winner)"""
    clear_screen()
    print_header("WON AUCTIONS")
    
    if not node.my_won_auctions:
        print_warning("You haven't won any auctions yet")
        press_enter_to_continue()
        return
    
    print(f"\nTotal won auctions: {len(node.my_won_auctions)}\n")
    
    for auction_id in node.my_won_auctions:
        auction = node.auction_manager.get_auction(auction_id)
        
        if not auction:
            print_warning(f"Auction {auction_id} not found in blockchain")
            continue
        
        # Get auction result
        result_data = None
        for block in reversed(node.blockchain.chain):
            for tx in block.transactions:
                if tx.get('type') == 'auction_result':
                    data = tx.get('data', {})
                    if data.get('auction_id') == auction_id:
                        result_data = data
                        break
            if result_data:
                break
        
        # Find my winning bid
        my_winning_bid = None
        for secret_key, secret_data in node.my_secrets.items():
            if (secret_data.get('type') == 'bidder' and
                secret_data.get('auction_id') == auction_id):
                my_winning_bid = secret_data
                break
        
        print("-"*60)
        print(f"🏛️  Auction ID: {auction_id[:16]}...")
        print(f"🏆 Item: {auction.item_description}")
        
        if my_winning_bid:
            print(f"💰 My winning bid: {my_winning_bid['bid_value']}€")
        
        print(f"📅 Start: {format_timestamp(auction.start_time)}")
        print(f"⏰ End: {format_timestamp(auction.end_time)}")
        
        print("-"*60)
        print()
    
    press_enter_to_continue()


def cli_close_auction(node):
    """CLI: Close auction"""
    clear_screen()
    print_header("CLOSE AUCTION")
    
    my_auctions = [aid for aid, secret in node.my_secrets.items() 
                if secret.get('type') == 'seller']
    
    if not my_auctions:
        print_warning("You have no auctions to close")
        press_enter_to_continue()
        return
    
    server_time = node.get_server_time()
    
    print("\nMy Auctions:")
    for i, auction_id in enumerate(my_auctions, 1):
        auction = node.auction_manager.get_auction(auction_id)
        if auction:
            status = node.auction_manager.get_auction_status(auction_id, current_time = server_time)
            print(f"\n{i}. {auction.item_description} ({auction_id})")
            print(f"   Status: {status.value}")
    
    idx = get_input(f"Choose auction (1-{len(my_auctions)})", int, lambda x: 1 <= x <= len(my_auctions))
    auction_id = my_auctions[idx - 1]
    
    if get_confirmation("Close and determine winner?"):
        node.close_and_finalize_auction(auction_id)
    
    press_enter_to_continue()


def cli_mine_block(node):
    """CLI: Mine block"""
    clear_screen()
    print_header("MINE BLOCK")
    
    print_info(f"Pending transactions: {len(node.blockchain.pending_transactions)}")
    
    if node.blockchain.pending_transactions:
        if get_confirmation("Mine block now?"):
            print_progress("Mining...", 2)
            node.mine_block()
    else:
        print_warning("No pending transactions")
    
    press_enter_to_continue()


def cli_view_blockchain(node):
    """CLI: View blockchain"""
    clear_screen()
    print_header("BLOCKCHAIN")
    
    print_info(f"Total blocks: {len(node.blockchain.chain)}")
    print_info(f"Last hash: {node.blockchain.get_last_block_hash()[:32]}...")
    
    if get_confirmation("View block details?"):
        for block in node.blockchain.chain[-5:]:  # Last 5
            print(f"\nBlock #{block.index}")
            print(f"  Hash: {block.hash[:32]}...")
            print(f"  Transactions: {len(block.transactions)}")
            print(f"  Timestamp: {format_timestamp(block.timestamp)}")
    
    press_enter_to_continue()


def cli_view_peers(node):
    """CLI: View peers"""
    clear_screen()
    print_header("CONNECTED PEERS")
    
    active_peers = node.get_active_peers_count()
    
    print_info(f"Connected peers (active): {active_peers}")
    print_info(f"Ring size: {len(node.ring_keys)}")
    
    if active_peers < len(node.ring_keys) - 1:
        offline_count = len(node.ring_keys) - 1 - active_peers
        print_warning(f"Some users are offline ({offline_count} offline)")
    
    press_enter_to_continue()


# ========== MAIN ==========
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Use: python node.py <username>")
        print("Example: python node.py Alice")
        sys.exit(1)
    
    username = sys.argv[1]
    
    node = AuctionNode(username, p2p_port=None)
    node.start()
    
    # Run CLI
    try:
        run_cli(node)
    except KeyboardInterrupt:
        print("\n")
    finally:
        print_info(f"Node {username} closed")