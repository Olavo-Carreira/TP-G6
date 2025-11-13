import socket
import requests
import time
import threading
from blockchain import Blockchain
from network import start_p2p_server, connect_to_peer, send_message, broadcast_to_peers, receive_message
from crypto_utils import generate_keypair, serialize_key, deserialize_key
from ring import create_ring_signature, verify_ring_signature
import json


class AuctionNode:
    def __init__(self, username, server_url='http://localhost:5001', p2p_port=None):
        self.username = username
        self.server_url = server_url
        
        # Gerar chaves
        self.private_key, self.public_key = generate_keypair()
        
        # Blockchain local
        self.blockchain = Blockchain()
        
        # P2P
        self.p2p_port = p2p_port or self._find_free_port()
        self.peer_sockets = []  # Lista de conexões ativas
        
        print(f"Nó {username} criado na porta {self.p2p_port}")
    
    def _listen_to_peer(self, peer_socket):
        """Loop de receção para sockets criadas via connect_to_peer"""
        
        try:
            while True:
                message = receive_message(peer_socket)
                if message is None:
                    # Pode ser timeout ou peer fechou
                    print("Peer fechou a ligacao ou timeout")
                    break
                # Reutilizas o mesmo handler que o servidor já usa
                self.handle_p2p_message(message, peer_socket)
        except Exception as e:
            print(f"Erro na thread de listen do peer: {e}")
        finally:
            try:
                peer_socket.close()
            except:
                pass
            if peer_socket in self.peer_sockets:
                self.peer_sockets.remove(peer_socket)
            print("Ligacao ao peer removida")

    def _find_free_port(self):
        """Encontrar porta livre automaticamente"""
        
        with socket.socket() as s:
            s.bind(('', 0))
            return s.getsockname()[1]
    
    # Init
    
    def start(self):
        """Iniciar nó completo"""
        
        print(f"\n{'='*50}")
        print(f"Iniciando nó {self.username}...")
        print(f"{'='*50}\n")
        
        # Registar no servidor
        self.register_with_server()
        
        # Iniciar servidor P2P
        self.start_p2p_server()
        
        # Anunciar presença
        self.announce_to_server()
        
        # Descobrir e conectar a peers
        self.discover_and_connect_peers()
        
        # Sincronizar blockchain
        self.sync_blockchain()
        
        print(f"\nNó {self.username} pronto!\n")
    
    # Server
    
    def register_with_server(self):
        
        """Registar no servidor central"""
        
        try:
            pub_key_bytes = serialize_key(self.public_key, is_private=False)
            
            response = requests.post(f'{self.server_url}/register', json={
                'username': self.username,
                'public_key': pub_key_bytes.decode('utf-8')
            })
            
            if response.status_code == 200:
                print(f"Registado no servidor")
            else:
                print(f"Falha no registo: {response.text}")
        
        except Exception as e:
            print(f"Erro ao registar: {e}")
        
        self.blockchain.add_transaction({
        'type': 'USER_REGISTRATION',
        'username': self.username,
        'public_key': pub_key_bytes.decode('utf-8'),
        'timestamp': time.time()
        })
    
    def announce_to_server(self):
        """Anunciar presença ao servidor"""
        
        try:
            response = requests.post(f'{self.server_url}/peers/announce', json={
                'peer_id': self.username,
                'port': self.p2p_port
            })
            
            if response.status_code == 200:
                print(f"Presença anunciada")
        
        except Exception as e:
            print(f"Erro ao anunciar: {e}")
    
    def get_peers_from_server(self):
        """Obter lista de peers do servidor"""
        
        try:
            response = requests.get(f'{self.server_url}/peers/list')
            
            if response.status_code == 200:
                data = response.json()
                peers = data.get('peers', [])
                # Filtrar self
                peers = [p for p in peers if p.get('ip') != '127.0.0.1' or p.get('port') != self.p2p_port]
                return peers
            
        except Exception as e:
            print(f"Erro ao obter peers: {e}")
        
        return []
    
    # P2P
    
    def start_p2p_server(self):
        """Iniciar servidor P2P"""
        
        start_p2p_server(self.p2p_port, self.handle_p2p_message)
        print(f"Servidor P2P iniciado na porta {self.p2p_port}")
    
    def discover_and_connect_peers(self):
        """Descobrir e conectar a peers"""
        
        peers = self.get_peers_from_server()
        
        print(f"Descobertos {len(peers)} peers")
        
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
        """Handler para mensagens P2P recebidas"""
        
        if sender_socket not in self.peer_sockets:
            self.peer_sockets.append(sender_socket)
            print(f"Peer adicionado à lista (total: {len(self.peer_sockets)})")
    
        msg_type = message.get('type')
        print(f"Recebido: {msg_type}")
        
        if msg_type == 'REQUEST_BLOCKCHAIN':
            self.send_blockchain(sender_socket)
        
        elif msg_type == 'BLOCKCHAIN':
            self.receive_blockchain(message)
        
        elif msg_type == 'NEW_BLOCK':
            self.receive_new_block(message)
        
        else:
            print(f"Tipo desconhecido: {msg_type}")
    
    # Sync
    
    def sync_blockchain(self):
        """Sincronizar blockchain com peers"""
        
        if not self.peer_sockets:
            print("Sem peers, usando blockchain local")
            return
        
        print("Sincronizando blockchain...")
        
        # Pedir blockchain ao primeiro peer
        request = {'type': 'REQUEST_BLOCKCHAIN'}
        send_message(self.peer_sockets[0], request)
    
    def send_blockchain(self, peer_socket):
        """Enviar blockchain para peer"""
        
        chain_data = [block.to_dict() for block in self.blockchain.chain]
        
        response = {
            'type': 'BLOCKCHAIN',
            'chain': chain_data
        }
        
        send_message(peer_socket, response)
    
    def receive_blockchain(self, message):
        """Receber blockchain de peer"""
        
        from block import Block
        
        chain_data = message.get('chain', [])
        received_chain = [Block.from_dict(b) for b in chain_data]
        
        if self.blockchain.replace_chain(received_chain):
            print("Blockchain atualizada")
        else:
            print("Blockchain local já está atualizada")
    
    def receive_new_block(self, message):
        """Receber novo bloco de peer"""
        
        from block import Block
        
        block_data = message.get('block')
        new_block = Block.from_dict(block_data)
        
        try:
            self.blockchain.add_block(new_block)
            print(f"Novo bloco #{new_block.index} adicionado")
        except Exception as e:
            print(f"Bloco rejeitado: {e}")

    def mine_test_block(self):
        """Minerar bloco de teste e broadcast"""
        
        print("\nMinerando bloco...")
        print(f"DEBUG: Peers antes broadcast = {len(self.peer_sockets)}")
        # Adicionar transação teste
        self.blockchain.add_transaction({
            'type': 'TEST',
            'from': self.username,
            'data': f'Teste de {self.username}'
        })
        
        # Minerar
        new_block = self.blockchain.mine_pending_transactions()
        
        if new_block:
            print(f"Bloco #{new_block.index} minerado!")
            
            for i, sock in enumerate(self.peer_sockets):
                print(f"DEBUG: Socket {i} = {sock}")
            
            message = {
                'type': 'NEW_BLOCK',
                'block': new_block.to_dict()
            }
            broadcast_to_peers(self.peer_sockets, message)
            
            print(f"Bloco enviado para {len(self.peer_sockets)} peers")
        
        return new_block

"""
    def create_test_certificate(self):
        ""Criar certificado de teste com ring signature usando blockchain""
        
        print("\n" + "="*50)
        print("Criando Certificado Ring Signature")
        print("="*50)
        
        # 1. Obter chaves públicas da BLOCKCHAIN (não do servidor!)
        print("\nBuscando chaves publicas na blockchain...")
        
        user_registrations = self.blockchain.get_transactions_by_type('USER_REGISTRATION')
        
        if len(user_registrations) < 2:
            print("Precisa de pelo menos 2 peers registados na blockchain")
            print(f"   Atual: {len(user_registrations)} peers")
            print("Dica: Outros peers precisam se registar e minerar blocos")
            return
        
        # Extrair chaves públicas únicas (evitar duplicatas)
        all_public_keys = []
        registered_users = set()
        
        for tx in user_registrations:
            username = tx.get('username')
            pub_key = tx.get('public_key')
            
            # Evitar duplicatas (mesmo user pode ter múltiplos registos)
            if username not in registered_users and pub_key:
                all_public_keys.append(pub_key)
                registered_users.add(username)
        
        print(f"Ring com {len(all_public_keys)} membros da blockchain")
        print(f"   Peers: {', '.join(registered_users)}")
        
        # Verificar se nossa chave está no ring
        our_key = serialize_key(self.public_key, is_private=False).decode('utf-8')
        if our_key not in all_public_keys:
            print("Sua chave nao esta na blockchain ainda!")
            print("Minerando bloco de registo...")
            
            # Minerar bloco com nosso registo
            new_block = self.blockchain.mine_pending_transactions()
            if new_block:
                print(f"Bloco #{new_block.index} minerado com seu registo")
                
                # Broadcast do bloco
                message = {
                    'type': 'NEW_BLOCK',
                    'block': new_block.to_dict()
                }
                broadcast_to_peers(self.peer_sockets, message)
                
                # Adicionar nossa chave ao ring
                all_public_keys.append(our_key)
                registered_users.add(self.username)
            else:
                print("Falha ao minerar bloco")
                return
        
        # 2. Criar mensagem do certificado
        certificate_data = {
            'issuer': 'anonymous',  # Anônimo!
            'timestamp': time.time(),
            'data': f'Certificado de teste - Ring de {len(all_public_keys)} peers',
            'type': 'test_certificate',
            'ring_members': list(registered_users)  # Para debug (pode remover)
        }
        
        message = json.dumps(certificate_data, sort_keys=True)
        
        # 3. Criar ring signature
        print("\nCriando ring signature...")
        
        try:
            ring_sig = create_ring_signature(
                message,
                self.private_key,
                all_public_keys
            )
            
            print(f"Ring signature criada")
            print(f"   - Ring size: {ring_sig['ring_size']}")
            print(f"   - Key image: {ring_sig['key_image'][:16]}...")
            
        except ValueError as e:
            print(f"Erro ao criar ring signature: {e}")
            return
        
        # 4. Criar certificado completo
        certificate = {
            'data': certificate_data,
            'ring_signature': ring_sig,
            'public_keys': all_public_keys
        }
        
        # 5. Verificar ring signature
        print("\nVerificando ring signature...")
        
        is_valid = verify_ring_signature(
            message,
            ring_sig,
            all_public_keys
        )
        
        if is_valid:
            print("Ring signature VALIDA")
            print("   -> Assinatura verificada SEM revelar identidade!")
        else:
            print("Ring signature INVALIDA")
        
        # 6. Mostrar resumo
        print("\n" + "="*50)
        print("CERTIFICADO CRIADO")
        print("="*50)
        print(f"Tipo: {certificate_data['type']}")
        print(f"Timestamp: {certificate_data['timestamp']}")
        print(f"Ring size: {len(all_public_keys)} membros")
        print(f"Fonte: Blockchain (transacoes USER_REGISTRATION)")
        print(f"Membros: {', '.join(registered_users)}")
        print(f"Anonimo: SIM (impossivel saber quem assinou)")
        print(f"Verificavel: {'SIM' if is_valid else 'NAO'}")
        print("="*50 + "\n")
        
        # 7. OPCIONAL: Adicionar certificado à blockchain
        print("Deseja adicionar este certificado a blockchain? (s/n)")
        choice = input("> ").lower()
        
        if choice == 's':
            self.blockchain.add_transaction({
                'type': 'RING_CERTIFICATE',
                'certificate': certificate_data,
                'ring_signature': ring_sig,
                'timestamp': time.time()
            })
            print("Certificado adicionado as transacoes pendentes")
            print("Use 'm' para minerar e propagar")
        
        return certificate
"""


# ========== TESTE ==========
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python node.py <username> [porta]")
        print("Exemplo: python node.py Alice 8000")
        sys.exit(1)
    
    username = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    node = AuctionNode(username, p2p_port=port)
    node.start()
    
    print("\nComandos disponiveis:")
    print("  m - Minerar bloco")
    print("  b - Ver blockchain")
    print("  c - Criar certificado ring signature")
    print("  q - Sair\n")

    while True:
        cmd = input("> ")
        
        if cmd == 'm':
            print(f"Peers conectados: {len(node.peer_sockets)}")
            node.mine_test_block()
        elif cmd == 'b':
            print(f"Chain: {len(node.blockchain.chain)} blocos")
        elif cmd == 'c':
            node.create_test_certificate()
        elif cmd == 'q':
            break
    
    # Manter vivo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\nEncerrando {username}...")
