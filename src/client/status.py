from enum import Enum

class AuctionStatus(Enum):

    ANNOUNCED = "announced"
    ACTIVE = "active"
    BIDDING_CLOSED = "bidding_closed"
    REVEALING = "revealing"
    COMPLETED = "completed"
