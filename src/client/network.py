import socket
import json
import threading
import time
import struct

"""P2P communication with TCP sockets"""

BUFFER_SIZE = 4096
TIMEOUT = 10

# ======== Auxiliary I/O functions ========

def recvall(sock, n):
    """
    Read exactly n bytes from socket (or return None if connection closes).
    """
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# ======== Server ========

def accept_connections(server_socket, message_handler):
    """Accept new connections"""
    
    while True:
        try:
            client_socket, address = server_socket.accept()
            print(f"New connection {address}")
            
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, address, message_handler)
            )
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            print(f"Error accepting connection: {e}")


def start_p2p_server(port, message_handler):
    """Start P2P server"""
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    
    print(f"P2P server listening on port {port}")
    
    thread = threading.Thread(
        target=accept_connections,
        args=(server_socket, message_handler) 
    )
    thread.daemon = True
    thread.start()
    
    return server_socket


def handle_client(client_socket, address, message_handler):
    """Handle messages from connected client"""
    
    try:
        while True:
            message = receive_message(client_socket)
            if message is None:
                break

            # Call node handler
            message_handler(message, client_socket)

    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        client_socket.close()
        print(f"Connection closed with {address}")

# ======== Client ========

def connect_to_peer(ip, port):
    """Connect to another P2P node"""
    
    try:
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.settimeout(None)
        peer_socket.connect((ip, port))
        print(f"Connected to {ip}:{port}")
        return peer_socket
    
    except Exception as e:
        print(f"Failed to connect to {ip}:{port}: {e}")
        return None


def send_message(peer_socket, message_dict):
    """Send JSON message to peer (with size prefix)"""
    
    try:
        message_json = json.dumps(message_dict).encode('utf-8')
        # 4 bytes with message size
        header = struct.pack('>I', len(message_json))
        peer_socket.sendall(header + message_json)
        return True
    
    except Exception as e:
        print(f"Error sending message: {e}")
        return False


def receive_message(peer_socket):
    """Receive JSON message from peer (with size prefix)"""
    
    try:
        # 1) Read 4 bytes with size
        raw_len = recvall(peer_socket, 4)
        if not raw_len:
            return None

        msg_len = struct.unpack('>I', raw_len)[0]

        # 2) Read exactly msg_len bytes
        data = recvall(peer_socket, msg_len)
        if not data:
            return None

        # 3) Decode JSON
        message = json.loads(data.decode('utf-8'))
        return message
    
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None
    
# ======== Broadcast ========

def broadcast_to_peers(peer_sockets, message_dict):
    """Send message to all connected peers"""
    
    print(f"DEBUG broadcast: Sending to {len(peer_sockets)} peers")
    
    failed_peers = []
    
    for i, peer_socket in enumerate(peer_sockets):
        print(f"DEBUG: Trying to send to peer {i}...")

        if not send_message(peer_socket, message_dict):
            print(f"DEBUG: FAILED peer {i}")
            failed_peers.append(peer_socket)
        else:
            print(f"DEBUG: SUCCESS peer {i}")
    for failed in failed_peers:
        try:
            failed.close()
            peer_sockets.remove(failed)
        except:
            pass
        
    print(f"Broadcast sent to {len(peer_sockets)} peers")

