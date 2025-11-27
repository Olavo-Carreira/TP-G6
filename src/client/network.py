import socket
import json
import threading
import time
import struct  # <--- NOVO

"""Comunicacao P2P com sockets TCP"""

BUFFER_SIZE = 4096
TIMEOUT = 10

# ======== Funções auxiliares de I/O ========

def recvall(sock, n):
    """
    Ler exatamente n bytes do socket (ou devolver None se a conexão fechar).
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
    """Aceitar novas conexoes"""
    
    while True:
        try:
            client_socket, address = server_socket.accept()
            print(f"Nova conexao {address}")
            
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, address, message_handler)
            )
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            print(f"Erro ao aceitar conexao: {e}")


def start_p2p_server(port, message_handler):
    """Iniciar servidor P2P"""
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    
    print(f"Server P2P escutando na porta {port}")
    
    thread = threading.Thread(
        target=accept_connections,
        args=(server_socket, message_handler) 
    )
    thread.daemon = True
    thread.start()
    
    return server_socket


def handle_client(client_socket, address, message_handler):
    """Lidar com mensagens de cliente que esta conectado"""
    
    try:
        while True:
            message = receive_message(client_socket)
            if message is None:
                break

            # Chamar o handler do node
            message_handler(message, client_socket)

    except Exception as e:
        print(f"Erro ao lidar com cliente {address}: {e}")
    finally:
        client_socket.close()
        print(f"Conexao fechada com {address}")

# ======== Cliente ========

def connect_to_peer(ip, port):
    """Conectar a outro no P2P"""
    
    try:
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.settimeout(None)
        peer_socket.connect((ip, port))
        print(f"Conectado a {ip}:{port}")
        return peer_socket
    
    except Exception as e:
        print(f"Falha ao conectar a {ip}:{port}: {e}")
        return None


def send_message(peer_socket, message_dict):
    """Enviar mensagem JSON para peer (com prefixo de tamanho)"""
    
    try:
        message_json = json.dumps(message_dict).encode('utf-8')
        # 4 bytes com o tamanho da mensagem 
        header = struct.pack('>I', len(message_json))
        peer_socket.sendall(header + message_json)
        return True
    
    except Exception as e:
        print(f"Erro ao enviar mensagem: {e}")
        return False


def receive_message(peer_socket):
    """Receber mensagem JSON de peer (com prefixo de tamanho)"""
    
    try:
        # 1) Ler 4 bytes com o tamanho
        raw_len = recvall(peer_socket, 4)
        if not raw_len:
            return None

        msg_len = struct.unpack('>I', raw_len)[0]

        # 2) Ler exatamente msg_len bytes
        data = recvall(peer_socket, msg_len)
        if not data:
            return None

        # 3) Decodificar JSON
        message = json.loads(data.decode('utf-8'))
        return message
    
    except Exception as e:
        print(f"Erro ao receber mensagem: {e}")
        return None
    
# ======== Broadcast ========

def broadcast_to_peers(peer_sockets, message_dict):
    """Enviar mensagem para todos os peers conectados"""
    
    print(f"DEBUG broadcast: Enviando para {len(peer_sockets)} peers")
    
    failed_peers = []
    
    for i, peer_socket in enumerate(peer_sockets):
        print(f"DEBUG: Tentando enviar para peer {i}...")

        if not send_message(peer_socket, message_dict):
            print(f"DEBUG: FALHOU peer {i}")
            failed_peers.append(peer_socket)
        else:
            print(f"DEBUG: SUCESSO peer {i}")
    for failed in failed_peers:
        try:
            failed.close()
            peer_sockets.remove(failed)
        except:
            pass
        
    print(f"Broadcast enviado para {len(peer_sockets)} peers")



if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python network.py <porta>")
        print("Exemplo: python network.py 8000")
        sys.exit(1)
    
    port = int(sys.argv[1])
    
    # Handler de mensagens de teste
    def test_handler(message, sender_socket):
        print(f"Mensagem recebida: {message}")
        
        # Responder
        response = {'type': 'ACK', 'message': 'Recebi!'}
        send_message(sender_socket, response)
    
    # Iniciar servidor
    start_p2p_server(port, test_handler)
    
    print("\nServidor iniciado. Para testar:")
    print(f"1. Abrir outro terminal")
    print(f"2. python")
    print(f"3. >>> from network import connect_to_peer, send_message")
    print(f"4. >>> s = connect_to_peer('localhost', {port})")
    print(f"5. >>> send_message(s, {{'type': 'test', 'data': 'hello'}})")
    
    # Manter vivo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nEncerrando...")
