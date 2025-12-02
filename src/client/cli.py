import time
import sys
from typing import List, Any

def print_header(title, width=60):
    print("\n" + "="*width)
    print(f"{title:^{width}}")
    print("="*width)


def print_box(title, lines, width=60):
    print("\n╔" + "═"*(width-2) + "╗")
    print(f"║ {title:^{width-4}} ║")
    print("╠" + "═"*(width-2) + "╣")
    for i, line in enumerate(lines):
        if i < 3:
            print(f"║ {line:<{width-5}} ║")
        elif i == 3:
            print(f"║ {line:<{width-3}} ║")
        elif i  == 5:
            print(f"║ {line:<{width-3}} ║")
        else:
            print(f"║ {line:<{width-5}} ║")
    
    print("╚" + "═"*(width-2) + "╝")


def print_menu(title, options, width=60):
    print("\n╔" + "═"*(width-2) + "╗")
    print(f"║ {title:^{width-4}} ║")
    print("╠" + "═"*(width-2) + "╣")
    
    for i, option in enumerate(options, 1):
        if i < 5:
            print(f"║ {i}. {option:<{width-8}} ║")
        elif i == 5:
            print(f"║ {i}. {option:<{width-6}} ║")
        elif i == 6:
            print(f"║ {i}. {option:<{width-8}} ║")
        elif i == 7:
            print(f"║ {i}. {option:<{width-6}} ║")
        elif 7 < i < 10: 
            print(f"║ {i}. {option:<{width-8}} ║")
        else:
            print(f"║ {i}. {option:<{width-9}} ║")
    
    print("╚" + "═"*(width-2) + "╝")


def print_success(message):
    print(f"✅ {message}")


def print_error(message):
    print(f"❌ {message}")


def print_warning(message):
    print(f"⚠️  {message}")


def print_info(message):
    print(f"ℹ️  {message}")


def print_auction_details(auction, status=None):
    print("\n" + "-"*60)
    print(f"🏛️  Auction ID: {auction.auction_id}")
    print(f"📦 Item: {auction.item_description}")
    print(f"⏰ Start: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(auction.start_time))}")
    print(f"⏰ End: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(auction.end_time))}")
    if status:
        print(f"📊 Status: {status.value}")
    print("-"*60)


def print_bid_details(bid):
    print(f"  💰 Bid ID: {bid.bid_id}")
    print(f"     Amount: {bid.bid_value:.2f}€")
    print(f"     Time: {time.strftime('%H:%M:%S', time.localtime(bid.timestamp))}")


def print_table(headers: List[str], rows: List[List[Any]], widths: List[int] = None):
    if not widths:
        widths = [max(len(str(row[i])) for row in [headers] + rows) + 2 for i in range(len(headers))]
    
    # Top line
    print("\n┌" + "┬".join("─"*w for w in widths) + "┐")
    
    # Headers
    print("│" + "│".join(f"{headers[i]:^{widths[i]}}" for i in range(len(headers))) + "│")
    
    # Separator line
    print("├" + "┼".join("─"*w for w in widths) + "┤")
    
    # Data rows
    for row in rows:
        print("│" + "│".join(f"{str(row[i]):<{widths[i]}}" for i in range(len(row))) + "│")
    
    # Bottom line
    print("└" + "┴".join("─"*w for w in widths) + "┘")


def get_input(prompt, input_type=str, validator=None):
    while True:
        try:
            value = input(f"➤ {prompt}: ")
            
            # Convert to correct type
            if input_type != str:
                value = input_type(value)
            
            # Validate if validator provided
            if validator and not validator(value):
                print_error("Wrong value, please try again")
                continue
            
            return value
            
        except ValueError:
            print_error(f"Please enter a valid {input_type.__name__} input")
        except KeyboardInterrupt:
            print("\n")
            raise


def get_confirmation(prompt):
    while True:
        response = input(f"➤ {prompt} (y/n): ").lower().strip()
        if response in ['s', 'sim', 'y', 'yes']:
            return True
        elif response in ['n', 'nao', 'não', 'no']:
            return False
        else:
            print_error("Please enter 'y' or 'n'")


def print_progress(message, duration=2):
    
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r{frames[i % len(frames)]} {message}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write(f"\r✅ {message} - Completed!\n")
    sys.stdout.flush()


def clear_screen():
    """Clear the screen"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def press_enter_to_continue():
    """Wait for the user to press Enter"""
    input("\n[Press Enter to continue...]")


def print_node_status(node):
    active_auctions = node.get_active_auctions()
    print(f"\nDEBUG: Active auctions returned: {len(active_auctions)}")
    for auction in active_auctions:
        print(f"  - {auction.auction_id}: {auction.item_description}")
        
    lines = [
        f"👤 User: {node.username}",
        f"🔗 Connected Peers: {node.get_active_peers_count()}",
        f"🔑 Ring Keys (total): {len(node.ring_keys)}",
        f"⛓️  Blocks in Chain: {len(node.blockchain.chain)}",
        f"📋 Pending Transactions: {len(node.blockchain.pending_transactions)}",
        f"🏛️  Active Auctions: {len(node.get_active_auctions())}",
    ]
    
    if abs(node.time_offset) > 5:
        lines.append(f"Clock offset {node.time_offset:+.1f}s")
        
    print_box("NODE STATUS", lines)


def format_timestamp(timestamp):
    """Format timestamp to readable string"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))


def format_currency(amount):
    """Format currency value"""
    return f"{amount:.2f}€"


def print_logo():
    """Print ASCII logo of the system"""
    logo = """
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║            🏛️  AUCTION SYSTEM P2P  🏛️               ║
    ║                                                   ║
    ║        Privacy-Preserving Auction System          ║
    ║        With Ring Signatures & Blockchain          ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """
    print(logo)


def print_divider(char="─", width=60):
    """Print divider line"""
    print(char * width)


