from typing import  List
import time

class AuctionResult:
    
    def __init__ (self, auction_id, winner_bid_id, winner_bid_commitment, winning_amount, reserve_price,
                    total_valid_bids, result_timestamp):
        self.auction_id = auction_id
        self.winner_bid_id = winner_bid_id
        self.winner_bid_commitment = winner_bid_commitment
        self.winning_amount = winning_amount
        self.reserve_price = reserve_price
        self.total_valid_bids = total_valid_bids
        self.result_timestamp = result_timestamp
        self.has_winner = winner_bid_commitment is not None
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'auction_id': self.auction_id,
            'winner_bid_id': self.winner_bid_id,
            'winner_bid_commitment': self.winner_bid_commitment,
            'winning_amount': self.winning_amount,
            'reserve_price': self.reserve_price,
            'total_valid_bids': self.total_valid_bids,
            'result_timestamp': self.result_timestamp,
            'has_winner': self.has_winner
        }
    
    def to_blockchain_transaction(self):
        """Convert to blockchain transaction"""
        return {
            'type': 'auction_result',
            'data': self.to_dict(),
            'timestamp': self.result_timestamp
        }
    

class WinnerDetermination:
    
    @staticmethod
    def determine_winner(auction_id, reserve_price, all_bids: List):
        """
        Determine auction winner
        """
        
        # Filter valid bids (above reserve price)
        valid_bids = [
            bid for bid in all_bids
            if bid.bid_value >= reserve_price
        ]
        
        if not valid_bids:
            # No winner
            winner_bid_id = None
            winner_commitment = None
            winning_amount = None
        else:
            valid_bids_sorted = sorted(
                valid_bids,
                key=lambda b: (-b.bid_value, b.timestamp)  # - for desc, without - for asc
            )
            
            winner_bid = valid_bids_sorted[0]
            
            tied_bids = [
                bid for bid in valid_bids
                if bid.bid_value == winner_bid.bid_value
            ]
            
            if len(tied_bids) > 1:
                print(f"\n⚠️  TIE DETECTED: {len(tied_bids)} bids with value {winner_bid.bid_value}€")
                print(f"   Winner chosen by timestamp (earliest): {winner_bid.timestamp}")
                for i, bid in enumerate(sorted(tied_bids, key=lambda b: b.timestamp)):
                    print(f"   #{i+1}: Bid {bid.bid_id[:8]}... @ timestamp {bid.timestamp}")
                print()
            
            # Extract winner data
            winner_bid_id = winner_bid.bid_id
            winner_commitment = winner_bid.bid_commitment
            winning_amount = winner_bid.bid_value
        
        # Create result
        result = AuctionResult(
            auction_id=auction_id,
            winner_bid_id=winner_bid_id,
            winner_bid_commitment=winner_commitment,
            winning_amount=winning_amount,
            reserve_price=reserve_price,
            total_valid_bids=len(valid_bids),
            result_timestamp=time.time()
        )
        
        return result