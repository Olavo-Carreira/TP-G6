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

        return {
            'type': 'auction_result',
            'data': self.to_dict(),
            'timestamp': self.result_timestamp
        }
    

class WinnerDetermination:
    
    @staticmethod
    def determine_winner(auction_id, reserve_price, all_bids: List):
        
        valid_bids = [
            bid for bid in all_bids
            if bid.bid_value >= reserve_price
        ]
        
        if valid_bids:
            winner_bid = max(valid_bids, key = lambda b : b.bid_value)
            winner_bid_id = winner_bid.bid_id
            winner_commitment = winner_bid.bid_commitment
            winning_amount = winner_bid.bid_value
        else:
            winner_bid_id = None
            winner_commitment = None
            winning_amount = None
            
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