import time
from typing import Dict, List

from announcement import AuctionAnnouncement
from bid import Bid
from status import AuctionStatus
from winner import WinnerDetermination, AuctionResult
from reveal import IdentityRevealManager, IdentityReveal
from blockchain import Blockchain
from commitement import verify_commitment

class AuctionManager:
    """Manages auctions and bids"""
    
    def __init__(self, blockchain=None):
        self.auctions: Dict[str, AuctionAnnouncement] = {}
        self.bids: Dict[str, List[Bid]] = {}  
        self.auction_status: Dict[str, AuctionStatus] = {}
        self.blockchain = blockchain  
        self.identity_manager = IdentityRevealManager()
    
    def create_auction_announcement(self, seller_private_key,  item_description, reserve_price,
        duration_seconds, ring_public_keys, start_timestamp = None, timestamp_signature = None, timestamp_hash = None):
        """Create new announcement"""

        announcement, reserve_nonce = AuctionAnnouncement.create(
            seller_private_key=seller_private_key,
            item_description=item_description,
            reserve_price=reserve_price,
            duration_seconds=duration_seconds,
            ring_public_keys=ring_public_keys,
            start_timestamp = start_timestamp,
            timestamp_signature = timestamp_signature,
            timestamp_hash = timestamp_hash
        )
        
        self.auctions[announcement.auction_id] = announcement
        self.bids[announcement.auction_id] = []
        self.auction_status[announcement.auction_id] = AuctionStatus.ANNOUNCED
        
        if self.blockchain:
            tx = announcement.to_blockchain_transaction()
            self.blockchain.add_transaction(tx)
        
        return announcement, reserve_nonce
    
    def submit_bid(self, auction_id, bidder_private_key,  bid_amount, ring_public_keys, bid_timestamp = None, timestamp_signature = None, timestamp_hash = None):
        """Submit a bid"""

        if auction_id not in self.auctions:
            raise ValueError(f"Auction {auction_id} not found")
        
        auction = self.auctions[auction_id]
        
        check_time = bid_timestamp if bid_timestamp else time.time()

        if check_time < auction.start_time:
            raise ValueError("Auction has not started yet")
        if check_time > auction.end_time:
            raise ValueError("Auction has ended")

        bid = Bid.create(
            auction_id = auction_id,
            bidder_private_key = bidder_private_key,
            bid_amount = bid_amount,
            ring_public_keys = ring_public_keys,
            bid_timestamp = bid_timestamp,
            timestamp_signature = timestamp_signature,
            timestamp_hash = timestamp_hash
        )

        self.bids[auction_id].append(bid)
        
        if self.auction_status[auction_id] == AuctionStatus.ANNOUNCED:
            self.auction_status[auction_id] = AuctionStatus.ACTIVE
        
        if self.blockchain:
            tx = bid.to_blockchain_transaction()
            self.blockchain.add_transaction(tx)
        
        return bid
    
    def verify_auction_announcement(self, announcement: AuctionAnnouncement, ring_public_keys = None):
        """Verify an announcement"""
        
        server_pubkey = self.blockchain.server_public_key if self.blockchain else None
        return announcement.verify(ring_public_keys, server_public_key=server_pubkey)
    
    def verify_bid(self, bid: Bid, ring_public_keys = None):
        """Verify a bid"""
        
        if bid.auction_id not in self.auctions:
            return False
        
        auction = self.auctions[bid.auction_id]
        server_pubkey = self.blockchain.server_public_key if self.blockchain else None
        
        return bid.verify(
            auction_start_time=auction.start_time,
            auction_end_time=auction.end_time,
            ring_public_keys=ring_public_keys,
            server_public_key=server_pubkey
        )
    
    def get_auction(self, auction_id):
        """Get auction by ID"""
        return self.auctions.get(auction_id)
    
    def get_auction_bids(self, auction_id):
        """Get bids for auction"""
        return self.bids.get(auction_id, [])
    
    def get_auction_status(self, auction_id, current_time = None):
        """Get auction status"""
        
        if auction_id not in self.auctions:
            return None
        
        if auction_id in self.auction_status:
            explicit_status = self.auction_status[auction_id]
            
            if explicit_status in [AuctionStatus.COMPLETED]:
                return explicit_status
            
        auction = self.auctions[auction_id]
        
        if current_time is None:
            current_time = time.time()
        
        if current_time < auction.start_time:
            return AuctionStatus.ANNOUNCED
        elif current_time <= auction.end_time:
            if auction_id in self.bids and len(self.bids[auction_id]) > 0:
                return AuctionStatus.ACTIVE
            else:
                return AuctionStatus.ANNOUNCED
        else:
            if auction_id in self.auction_status:
                return self.auction_status[auction_id]
            else:
                return AuctionStatus.BIDDING_CLOSED

        return self.auction_status.get(auction_id)
    
    def close_bidding(self, auction_id, current_time = None):
        """Close bidding period"""
        
        if auction_id not in self.auctions:
            return False
        
        auction = self.auctions[auction_id]
        
        if current_time is None:
            current_time = time.time()
        
        if current_time < auction.end_time:
            return False
        
        self.auction_status[auction_id] = AuctionStatus.BIDDING_CLOSED
        return True
    
    def get_all_auctions(self):
        """Get all auctions"""
        return list(self.auctions.values())
    
    def get_active_auctions(self, current_time = None):
        """Get active auctions"""
        
        if current_time is None:
            current_time = time.time()
            
        return [
            auction for auction in self.auctions.values()
            if auction.start_time <= current_time <= auction.end_time
        ]
    
    def finalize_auction(self, auction_id, reserve_price,reserve_nonce):
        """Determine winner and finalize auction"""
        
        if auction_id not in self.auctions:
            raise ValueError(f"Auction {auction_id} not found")
        
        if self.auction_status[auction_id] != AuctionStatus.BIDDING_CLOSED:
            raise ValueError("Auction must have bidding closed first")
        
        auction = self.auctions[auction_id]
        
        if not verify_commitment(
            auction.reserve_price_commitment,
            reserve_price,
            reserve_nonce,
            auction_id
        ):
            raise ValueError("Invalid reserve price reveal")
        
        all_bids = self.bids[auction_id]
        
        result = WinnerDetermination.determine_winner(
            auction_id = auction_id,
            reserve_price = reserve_price,
            all_bids = all_bids
        )
        
        self.auction_status[auction_id] = AuctionStatus.COMPLETED
        
        if self.blockchain:
            tx = result.to_blockchain_transaction()
            self.blockchain.add_transaction(tx)
        
        return result
    
    def seller_reveal_identity(self, auction_id, seller_public_key):
        """Seller reveals true identity after auction"""
        
        if auction_id not in self.auctions:
            raise ValueError(f"Auction {auction_id} not found")
        
        if self.auction_status[auction_id] != AuctionStatus.COMPLETED:
            raise ValueError("Auction must be completed first")

        reveal = self.identity_manager.reveal_seller_identity(
            auction_id = auction_id,
            seller_public_key = seller_public_key
        )
            
        return reveal
    
    def winner_reveal_identity(self, auction_id, winner_public_key, winning_bid_commitment):
        """Winner reveals identity"""
        
        if auction_id not in self.auctions:
            raise ValueError(f"Auction {auction_id} not found")
        
        if self.auction_status[auction_id] != AuctionStatus.COMPLETED:
            raise ValueError("Auction must be completed first")
        
        reveal = self.identity_manager.reveal_winner_identity(
            auction_id = auction_id,
            winner_public_key = winner_public_key,
            winning_bid_commitment = winning_bid_commitment
        )

        return reveal

    def load_from_blockchain(self, blockchain):
        """Reconstruct auctions and bids from blockchain"""
        
        # Load auction announcements
        auction_txs = blockchain.get_transactions_by_type('AUCTION_ANNOUNCE')
        for tx in auction_txs:
            data = tx['data'].copy()  # Copy to avoid modifying original
            # Add timestamp from transaction level if missing
            if 'timestamp' not in data:
                data['timestamp'] = tx.get('timestamp', time.time())
            announcement = AuctionAnnouncement.from_dict(data)
            self.auctions[announcement.auction_id] = announcement
            if announcement.auction_id not in self.bids:
                self.bids[announcement.auction_id] = []
            # Determine initial status
            current_time = time.time()
            if current_time > announcement.end_time:
                self.auction_status[announcement.auction_id] = AuctionStatus.BIDDING_CLOSED
            elif current_time >= announcement.start_time:
                self.auction_status[announcement.auction_id] = AuctionStatus.ACTIVE
            else:
                self.auction_status[announcement.auction_id] = AuctionStatus.ANNOUNCED
        
        # Load bids
        bid_txs = blockchain.get_transactions_by_type('BID')
        for tx in bid_txs:
            data = tx['data'].copy()  # Copy to avoid modifying original
            # Add timestamp from transaction level if missing
            if 'timestamp' not in data:
                data['timestamp'] = tx.get('timestamp', time.time())
            bid = Bid.from_dict(data)
            if bid.auction_id in self.bids:
                self.bids[bid.auction_id].append(bid)
        
        # Load results
        result_txs = blockchain.get_transactions_by_type('auction_result')
        for tx in result_txs:
            data = tx['data']
            auction_id = data['auction_id']
            if auction_id in self.auction_status:
                self.auction_status[auction_id] = AuctionStatus.COMPLETED


