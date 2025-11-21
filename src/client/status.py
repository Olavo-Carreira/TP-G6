from enum import Enum

class AuctionStatus(Enum):
    """Ciclo de vida da auction"""
    
    ANNOUNCED = "announced"
    ACTIVE = "active"
    BIDDING_CLOSED = "bidding_closed"
    REVEALING = "revealing"
    COMPLETED = "completed"
