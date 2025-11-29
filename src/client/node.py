"""
Auction Node - Nó P2P para sistema de leilões
Integra blockchain, networking, auction manager e CLI

✅ FIX: Removido processamento duplicado de transações em receive_new_block
"""

import socket
import requests
import time
import threading
import json
import logging
import hashlib

from blockchain import Blockchain
from network import start_p2p_server, connect_to_peer, send_message, broadcast_to_peers, receive_message
from crypto_utils import generate_keypair, serialize_key, deserialize_key
from manager import AuctionManager
from announcement import AuctionAnnouncement
from reveal import IdentityReveal
from bid import Bid
from commitement import save_secret_locally, load_secret_for_reveal, create_commitment
from cli import *
from status import AuctionStatus


# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class AuctionNode:
    """Nó P2P para participar em leilões anônimos"""
    
    def __init__(self, username, server_url='http://localhost:5001', p2p_port=None):
        self.username = username
        self.server_url = server_url
        
        # Gerar chaves criptográficas
        self.private_key, self.public_key = generate_keypair()
        logger.info(f"Chaves geradas para {username}")
        
        # Blockchain local
        self.blockchain = Blockchain(server_public_key = None)
        
        # Auction Manager (integração completa!)
        self.auction_manager = AuctionManager(self.blockchain)
        
        # P2P networking
        self.p2p_port = p2p_port or self._find_free_port()
        self.peer_sockets = []
        
        # Cache de ring keys
        self.ring_keys = []
        
        # Secrets locais (reserve prices e bid nonces)
        self.my_secrets = {}  # {auction_id: {'reserve_nonce': ..., 'type': 'seller'}}
        
        self.processed_bid_ids = set()
        
        self.time_offset = 0 # Possivel solucao para a questao do futuro na alice
        
        self.server_public_key = None
        
        logger.info(f"Nó {username} criado na porta {self.p2p_port}")
    
    def _find_free_port(self):
        """Encontrar porta livre automaticamente"""
        with socket.socket() as s:
            s.bind(('', 0))
            return s.getsockname()[1]
    
    def _listen_to_peer(self, peer_socket):
        """Thread para escutar mensagens de um peer"""
        try:
            while True:
                message = receive_message(peer_socket)
                if message is None:
                    logger.debug("Peer fechou a ligação")
                    break
                self.handle_p2p_message(message, peer_socket)
        except Exception as e:
            logger.error(f"Erro na thread de listen: {e}")
        finally:
            try:
                peer_socket.close()
            except:
                pass
            if peer_socket in self.peer_sockets:
                self.peer_sockets.remove(peer_socket)
    
    # ==================== INICIALIZAÇÃO ====================
    
    def start(self):
        """Iniciar nó completo"""
        print_header(f"INICIANDO NÓ {self.username}")
        
        # 1. Registar no servidor
        print_info("Registando no servidor central...")
        self.register_with_server()
        
        print_info("Sincronizando o relogio")
        if self.sync_time_with_server():
            print_success(f"Relogio sincronizado")
        else:
            print("Nao foi possivel sincronizar relogio")
            
        print_info("Obtendo chave do server")
        if self.get_server_public_key():
            print_success("Chave do servidor obtida")
        else:
            print_warning("Sem chave do servidor - timestamp nao verificaveis")
            
        # 2. Iniciar servidor P2P
        print_info("Iniciando servidor P2P...")
        self.start_p2p_server()
        
        # 3. Anunciar presença
        print_info("Anunciando presença...")
        self.announce_to_server()
        
        # 4. Descobrir e conectar a peers
        print_info("Descobrindo peers...")
        self.discover_and_connect_peers()
        
        # 5. Sincronizar blockchain
        print_info("Sincronizando blockchain...")
        self.sync_blockchain()
        
        # 6. Atualizar ring keys
        print_info("Atualizando ring de chaves...")
        self.update_ring_keys()

        print_success(f"Nó {self.username} pronto!")
        time.sleep(1)
    
    def register_with_server(self):
        """Registar no servidor central"""
        try:
            pub_key_bytes = serialize_key(self.public_key, is_private=False)
            pub_key_str = pub_key_bytes.decode('utf-8')
            
            existing_txs = self.blockchain.get_transactions_by_type('USER_REGISTRATION')
            for tx in existing_txs:
                if tx.get('public_key') == pub_key_str:
                    logger.info(f"Ja registado anteriormente")
                    return
            
            response = requests.post(f'{self.server_url}/register', json={
                'username': self.username,
                'public_key': pub_key_bytes.decode('utf-8')
            })
            
            if response.status_code == 200:
                # Adicionar à blockchain
                self.blockchain.add_transaction({
                    'type': 'USER_REGISTRATION',
                    'username': self.username,
                    'public_key': pub_key_bytes.decode('utf-8'),
                    'timestamp': time.time()
                })
                logger.info("Registado no servidor")
            else:
                logger.warning(f"Falha no registo: {response.text}")
        
        except Exception as e:
            logger.error(f"Erro ao registar: {e}")
    
    def announce_to_server(self):
        """Anunciar presença ao servidor"""
        try:
            response = requests.post(f'{self.server_url}/peers/announce', json={
                'peer_id': self.username,
                'port': self.p2p_port
            })
            
            if response.status_code == 200:
                logger.info("Presença anunciada")
        
        except Exception as e:
            logger.error(f"Erro ao anunciar: {e}")
    
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
            logger.error(f"Erro ao obter peers: {e}")
        
        return []
    
    def get_trusted_timestamp(self, data_hash):
        """Obter timestamp confiavel do server"""
        
        try:
            response = requests.post(f'{self.server_url}/timestamp', json = {
                'hash' : data_hash
            }, timeout = 5)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Timestamp server falhou")
                return None
        
        except Exception as e:
            logger.error(f"Erro timestamp: {e}")
            return None
    
    def get_trusted_time(self, data_for_hash=""):
        """Obter apenas o timestamp"""
        
        data_hash = hashlib.sha256(data_for_hash.encode()).hexdigest()
        ts_data = self.get_trusted_timestamp(data_hash)
        
        if ts_data:
            return {
                'timestamp': ts_data['timestamp'],
                'signature': ts_data['signature'],
                'hash': data_hash
            }
        else:
            logger.warning("Usando tempo local como fallback")
            return {
                'timestamp': time.time(),
                'signature': None,
                'hash': data_hash
            }
        
    def sync_time_with_server(self):
        """Calcular offset de tempo entre o server e local"""
        
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
                    logger.warning(f"Relogio dessincronizado: {self.time_offset:.2f}s de diferenca")
                else:
                    logger.info(f"Tempo sincronizado (offset: {self.time_offset:.3f}s)")
                
                return True
            
        except Exception as e:
            logger.error(f"Erro ao sincronizar tempo: {e}")
            self.time_offset = 0
        
        return False
    
    def get_server_public_key(self):
        """Obter chave publica do servidor para verificar timestamps"""
        
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
                    
                    logger.info("Chave publica do servidor obtida")
                    return self.server_public_key
        
        except Exception as e:
            logger.error(f"Erro ao obter chave do server: {e}")
            
        return None
    
    def get_server_time(self):
        """Tempo ajustado para servidor"""
        
        return time.time() + self.time_offset
    
    
    
    # ==================== P2P NETWORKING ====================
    
    def start_p2p_server(self):
        """Iniciar servidor P2P"""
        start_p2p_server(self.p2p_port, self.handle_p2p_message)
        logger.info(f"Servidor P2P na porta {self.p2p_port}")
    
    def discover_and_connect_peers(self):
        """Descobrir e conectar a peers"""
        peers = self.get_peers_from_server()
        logger.info(f"Descobertos {len(peers)} peers")
        
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
        Handler central para mensagens P2P
        
        ✅ COMPLETO: Trata todos os tipos de mensagens
        """
        # Adicionar socket à lista se novo
        if sender_socket not in self.peer_sockets:
            self.peer_sockets.append(sender_socket)
        
        msg_type = message.get('type')
        print(f"🔍 DEBUG handle_p2p_message: Recebido tipo={msg_type}")
        logger.debug(f"Recebido: {msg_type}")
        
        try:
            if msg_type == 'REQUEST_BLOCKCHAIN':
                self.send_blockchain(sender_socket)
            
            elif msg_type == 'BLOCKCHAIN':
                self.receive_blockchain(message)
            
            elif msg_type == 'NEW_BLOCK':
                self.receive_new_block(message)
            
            elif msg_type == 'AUCTION_ANNOUNCE':
                print(f"🔍 DEBUG: Vai chamar receive_auction_announcement")
                self.receive_auction_announcement(message)
            
            elif msg_type == 'BID':
                self.receive_bid(message)
            
            elif msg_type == 'AUCTION_RESULT':
                self.receive_auction_result(message)
            
            elif msg_type == 'IDENTITY_REVEAL':
                self.receive_identity_reveal(message)
            
            else:
                logger.warning(f"Tipo desconhecido: {msg_type}")
        
        except Exception as e:
            logger.error(f"Erro ao processar mensagem {msg_type}: {e}")
    
    # ==================== BLOCKCHAIN SYNC ====================
    
    def sync_blockchain(self):
        """Sincronizar blockchain com peers"""
        if not self.peer_sockets:
            logger.info("Sem peers, usando blockchain local")
            return
        
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
            logger.info("Blockchain atualizada")
            # ✅ ATUALIZAR RING após sincronizar
            self.update_ring_keys()
            # Reconstruir auction manager da blockchain
            self.rebuild_auction_manager_from_blockchain()
        else:
            logger.info("Blockchain local já está atualizada")
    
    def receive_new_block(self, message):
        """
        Receber novo bloco de peer
        
        ✅ FIX: Removido processamento duplicado - rebuild_auction_manager já processa tudo
        """
        from block import Block
        
        block_data = message.get('block')
        new_block = Block.from_dict(block_data)
        
        try:
            self.blockchain.add_block(new_block)
            logger.info(f"Bloco #{new_block.index} adicionado")
            
            # ✅ ATUALIZAR RING após receber bloco (pode ter novos registos!)
            self.update_ring_keys()
            
            # ✅ RECONSTRUIR AUCTION MANAGER (já processa todas as transações)
            self.rebuild_auction_manager_from_blockchain()
        
        except Exception as e:
            logger.warning(f"Bloco rejeitado: {e}")
    
    # ==================== AUCTION HANDLERS ====================
    
    def receive_auction_announcement(self, message):
        """Receber anúncio de leilão"""
        try:
            data = message.get('data')
            announcement = AuctionAnnouncement.from_dict(data)
            
            print(f"🔍 DEBUG: Announcement recebido - ID: {announcement.auction_id}")
            print(f"🔍 DEBUG: Ring keys disponíveis: {len(self.ring_keys)}")
            
            # Verificar validade
            if self.auction_manager.verify_auction_announcement(announcement):
                # Adicionar ao manager
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
                
                print_info(f"Novo leilão: {announcement.item_description} ({announcement.auction_id})")
                
                self.blockchain.add_transaction({
                    'type': 'AUCTION_ANNOUNCE',
                    'data': announcement.to_dict(),
                    'timestamp': announcement.timestamp
                })
                
                logger.debug(f"🔍 DEBUG: ANNOUNCEMENT adicionado à pool local")
                logger.debug(f"   Pool size agora: {len(self.blockchain.pending_transactions)}")
                logger.debug(f"   Auction ID: {announcement.auction_id}")
            else:
                logger.warning("Anúncio inválido recebido")
        
        except Exception as e:
            logger.error(f"Erro ao processar anúncio: {e}")
    
    def receive_bid(self, message):
        """Receber bid"""
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
                
                print_info(f"Nova bid de {bid.bid_value:.2f}€ no leilao {bid.auction_id}")
                
                self.blockchain.add_transaction({
                    'type': 'BID',
                    'data': bid.to_dict(),
                    'timestamp': bid.timestamp
                })
                
                logger.debug(f"🔍 DEBUG: BID adicionada à pool local")
                logger.debug(f"   Pool size agora: {len(self.blockchain.pending_transactions)}")
                logger.debug(f"   Bid ID: {bid.bid_id}")
            else:
                logger.warning("Bid invalida recebida")
                        
        except Exception as e:
            logger.error(f"Erro ao processar bid: {e}")
    
    def receive_auction_result(self, message):
        """Receber resultado de leilão"""
        try:
            data = message.get('data')
            auction_id = data.get('auction_id')
            
            if auction_id in self.auction_manager.auction_status:
                self.auction_manager.auction_status[auction_id] = AuctionStatus.COMPLETED
            
            if data.get('has_winner'):
                print_success(f"Leilão {auction_id} tem vencedor! Valor: {data.get('winning_amount')}€")
                
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
                    
                    print(f"DEBUG: Comparando commits")
                    print(f"Winning: {winning_commitment}")
                    print(f"Meu: {my_commitment}")
                    
                    if my_commitment == winning_commitment:
                        print_success("Ganhaste o leilao")
                        
                        winner_reveal = self.auction_manager.winner_reveal_identity(
                            auction_id = auction_id,
                            winner_public_key = self.public_key,
                            winning_bid_commitment = winning_commitment
                        )
                        
                        broadcast_to_peers(self.peer_sockets, {
                            'type': 'IDENTITY_REVEAL',
                            'data': winner_reveal.to_dict()
                        })
                        
                        print_info("identidade Revelada. Aguardando seller...")
                        break
            else:
                print_info(f"Leilão {auction_id} fechou sem vencedor")
        
        except Exception as e:
            logger.error(f"Erro ao processar resultado: {e}")
    
    def receive_identity_reveal(self, message):
        """Receber reveal de identidade"""
        try:
            
            data = message.get('data')
            reveal = IdentityReveal.from_dict(data)
            auction_id = reveal.auction_id
            role = reveal.role
            
            # ✅ DEBUG
            print(f"DEBUG: Recebi IDENTITY_REVEAL - role={role}, auction_id={auction_id}")
            print(f"DEBUG: Meu username={self.username}")
            
            # Guardar no identity_manager
            if reveal.role == "seller":
                self.auction_manager.identity_manager.identity_reveals.setdefault(auction_id, {})
                self.auction_manager.identity_manager.identity_reveals[auction_id]["seller"] = reveal
                print_info(f"Seller revelou identidade no leilão {auction_id}")
            
            elif reveal.role == "winner":
                self.auction_manager.identity_manager.identity_reveals.setdefault(auction_id, {})
                self.auction_manager.identity_manager.identity_reveals[auction_id]["winner"] = reveal
                print_info(f"Winner revelou identidade no leilão {auction_id}")
            
            # ✅ DEBUG
            reveals = self.auction_manager.identity_manager.identity_reveals.get(auction_id, {})
            print(f"DEBUG: Reveals guardados para {auction_id}: {list(reveals.keys())}")
            
            # ✅ VERIFICAR SE AMBOS REVELARAM
            if self.auction_manager.identity_manager.are_identities_revealed(auction_id):
                print(f"DEBUG: AMBOS REVELARAM! Vou mostrar info...")
                
                seller_reveal = self.auction_manager.identity_manager.get_seller_identity(auction_id)
                winner_reveal = self.auction_manager.identity_manager.get_winner_identity(auction_id)
                
                seller_username = self._get_username_from_pubkey(seller_reveal.public_key)
                winner_username = self._get_username_from_pubkey(winner_reveal.public_key)
                
                # Verificar se SOU o seller ou winner deste leilão
                my_pubkey_str = serialize_key(self.public_key, is_private=False).decode('utf-8')
                
                if seller_reveal.public_key == my_pubkey_str or winner_reveal.public_key == my_pubkey_str:
                    print("\n" + "="*60)
                    print_success("🎉 IDENTIDADES REVELADAS - INFORMAÇÃO DO LEILÃO")
                    print("="*60)
                    print(f"   🏛️  Auction ID: {auction_id}")
                    print(f"   👤 Seller: {seller_username}")
                    print(f"   🏆 Winner: {winner_username}")
                    print("="*60 + "\n")
            else:
                print(f"DEBUG: Ainda faltam reveals. Guardados: {list(reveals.keys())}")
        
        except Exception as e:
            logger.error(f"Erro ao processar reveal: {e}")
            import traceback
            traceback.print_exc()
    
    def process_transaction(self, tx):
        """
        Processar transação adicionada à blockchain
        
        ⚠️  DEPRECATED: Usar rebuild_auction_manager_from_blockchain() em vez disso
        """
        tx_type = tx.get('type')
        
        if tx_type == 'AUCTION_ANNOUNCE':
            self.receive_auction_announcement(tx)
        elif tx_type == 'BID':
            self.receive_bid(tx)
    
    def rebuild_auction_manager_from_blockchain(self):
        """
        Reconstruir auction manager a partir da blockchain
        
        Processa todos os leilões e bids da blockchain para reconstruir
        o estado do auction manager após sincronização.
        
        ✅ Este método já processa todas as transações, evitando duplicação
        """
        logger.info("Reconstruindo auction manager da blockchain...")
        
        # Processar todos os blocos
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
                        
                        # Adicionar ao manager sem verificar (já está na blockchain)
                        self.auction_manager.auctions[announcement.auction_id] = announcement
                        if announcement.auction_id not in self.auction_manager.bids:
                            self.auction_manager.bids[announcement.auction_id] = []
                        
                        # Determinar status baseado em timestamps
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
                        
                        logger.debug(f"Leilão reconstruído: {announcement.auction_id}")
                    
                    except Exception as e:
                        logger.error(f"Erro ao reconstruir leilão: {e}")
                
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
                        logger.error(f"Erro ao reconstruir bid: {e}")
        
        logger.info(f"Reconstrução completa: {len(self.auction_manager.auctions)} leilões")
    
    # ==================== AUCTION OPERATIONS ====================
    
    def create_auction(self, item_description, reserve_price, duration_minutes):
        """
        Criar novo leilão
        
        Args:
            item_description: Descrição do item
            reserve_price: Preço mínimo
            duration_minutes: Duração em minutos
            
        Returns:
            str: ID do leilão criado
        """
        try:
            print_progress("Criando leilão...", 1)
            
            trusted_time_data = self.get_trusted_time(f"{self.username}{item_description}{reserve_price}")
            
            ring_keys_to_use = self.get_ring_keys_for_signing()
            
            announcement, reserve_nonce = self.auction_manager.create_auction_announcement(
                seller_private_key=self.private_key,
                seller_public_key=self.public_key,
                item_description=item_description,
                reserve_price=reserve_price,
                duration_seconds=duration_minutes * 60,
                ring_public_keys=ring_keys_to_use,
                start_timestamp = trusted_time_data['timestamp'],
                timestamp_signature = trusted_time_data['signature'],
                timestamp_hash = trusted_time_data['hash']
            )
            
            # Guardar reserve nonce localmente
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
            
            # Broadcast para peers
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
            
            # Minerar bloco
            self.mine_block()
            
            print_success(f"Leilão criado! ID: {announcement.auction_id}")
            
            return announcement.auction_id
        
        except Exception as e:
            print_error(f"Erro ao criar leilão: {e}")
            return None
    
    def submit_bid(self, auction_id, bid_amount):
        """
        Submeter bid a um leilão
        
        Args:
            auction_id: ID do leilão
            bid_amount: Valor da bid
            
        Returns:
            bool: True se sucesso
        """
        try:
            
            if auction_id in self.my_secrets and self.my_secrets[auction_id].get('type') == 'seller':
                print_error("Nao se pode dar bid no seu proprio leilao")
                return False
            
            auction = self.auction_manager.get_auction(auction_id)
            if not auction:
                print_error("Leilao nao encontrado")
                return False
            
            existing_bids = self.auction_manager.get_auction_bids(auction_id)
            if existing_bids:
                max_bid = max(existing_bids, key = lambda b: b.bid_value)
                if bid_amount <= max_bid.bid_value:
                    print_error(f"Bid inferior a atual winner")
                    return False
            
            print_progress("Submetendo bid...", 1)
            
            trusted_time_data = self.get_trusted_time(f"{auction_id}{bid_amount}{self.username}")
            
            ring_keys_to_use = self.get_ring_keys_for_signing()
            
            bid = self.auction_manager.submit_bid(
                auction_id=auction_id,
                bidder_private_key=self.private_key,
                bidder_public_key=self.public_key,
                bid_amount=bid_amount,
                ring_public_keys=ring_keys_to_use,
                bid_timestamp = trusted_time_data['timestamp'],
                timestamp_signature = trusted_time_data['signature'],
                timestamp_hash = trusted_time_data['hash']
            )
            
            # Guardar bid nonce localmente
            self.my_secrets[f"bid_{bid.bid_id}"] = {
                'bid_nonce': bid.bid_nonce,
                'bid_value': bid_amount,
                'auction_id': auction_id,
                'type': 'bidder'
            }
            self.processed_bid_ids.add(bid.bid_id)
            
            save_secret_locally({
                'bid_id': bid.bid_id,
                'bid_nonce': bid.bid_nonce,
                'bid_value': bid_amount,
                'auction_id': auction_id,
                'type': 'bidder'
            })
            
            # Broadcast para peers
            message = {
                'type': 'BID',
                'data': bid.to_dict()
            }
            broadcast_to_peers(self.peer_sockets, message)
            
            # Minerar bloco
            self.mine_block()
            
            print_success(f"Bid submetida! Valor: {bid_amount}€")
            
            return True
        
        except Exception as e:
            print_error(f"Erro ao submeter bid: {e}")
            return False
    
    def close_and_finalize_auction(self, auction_id):
        """
        Fechar e finalizar leilão (apenas seller)
        
        Args:
            auction_id: ID do leilão
            
        Returns:
            bool: True se sucesso
        """
        try:
            
            server_time = self.get_server_time()
            
            # Verificar se é o seller
            if auction_id not in self.my_secrets or self.my_secrets[auction_id]['type'] != 'seller':
                print_error("Apenas o seller pode finalizar o leilão!")
                return False
            
            # Fechar bidding
            if not self.auction_manager.close_bidding(auction_id, current_time=server_time):
                print_error("Não foi possível fechar o leilão (ainda não terminou?)")
                return False
            
            print_progress("Determinando vencedor...", 1)
            
            # Finalizar com reserve price
            secret = self.my_secrets[auction_id]
            result = self.auction_manager.finalize_auction(
                auction_id=auction_id,
                reserve_price=secret['reserve_price'],
                reserve_nonce=secret['reserve_nonce']
            )
            
            # Broadcast resultado
            message = {
                'type': 'AUCTION_RESULT',
                'data': result.to_dict()
            }
            broadcast_to_peers(self.peer_sockets, message)
            
            # Minerar bloco
            self.mine_block()
            
            if result.has_winner:
                print_success(f"Vencedor determinado! Valor: {result.winning_amount}€")
                
                seller_reveal = self.auction_manager.seller_reveal_identity(
                    auction_id = auction_id,
                    seller_public_key = self.public_key
                )
                
                self.auction_manager.identity_manager.identity_reveals.setdefault(auction_id, {})
                self.auction_manager.identity_manager.identity_reveals[auction_id]["seller"] = seller_reveal
                
                broadcast_to_peers(self.peer_sockets, {
                    'type': 'IDENTITY_REVEAL',
                    'data': seller_reveal.to_dict()
                })
                
                print_info(f"Identidade do seller revelada. Aguardando winner ...")
            else:
                print_info("Leilão fechou sem vencedor (nenhuma bid atingiu reserve price)")
            
            return True
        
        except Exception as e:
            print_error(f"Erro ao finalizar leilão: {e}")
            return False
    
    def get_active_auctions(self):
        """Obter lista de leilões ativos"""
        
        server_time = self.get_server_time()
        
        return self.auction_manager.get_active_auctions(current_time=server_time)
    
    def get_auction_bids(self, auction_id):
        """Obter bids de um leilão"""
        return self.auction_manager.get_auction_bids(auction_id)
    

    
    # ==================== MINING ====================
    
    def mine_block(self):
        """Minerar bloco com transações pendentes"""
        
        logger.debug(f"🔍 DEBUG MINE: Pool tem {len(self.blockchain.pending_transactions)} transações")
        for tx in self.blockchain.pending_transactions:
            logger.debug(f"   - {tx.get('type')}")



        if not self.blockchain.pending_transactions:
            logger.debug("Sem transações pendentes para minerar")
            return None
        
        logger.info(f"Minerando bloco com {len(self.blockchain.pending_transactions)} transações")
        logger.debug(f"Previous hash: {self.blockchain.get_last_block_hash()[:16]}...")
        logger.debug(f"Chain length antes: {len(self.blockchain.chain)}")
        
        new_block = self.blockchain.mine_pending_transactions()
        
        if new_block:
            logger.info(f"Bloco #{new_block.index} minerado!")
            logger.debug(f"Novo hash: {new_block.hash[:16]}...")
            logger.debug(f"Chain length depois: {len(self.blockchain.chain)}")
            
            # Broadcast para peers
            message = {
                'type': 'NEW_BLOCK',
                'block': new_block.to_dict()
            }
            broadcast_to_peers(self.peer_sockets, message)
            logger.debug(f"Bloco enviado para {len(self.peer_sockets)} peers")
        
        return new_block
    
    # ==================== UTILITIES ====================
    
    def update_ring_keys(self):
        """Atualizar lista de ring keys da blockchain"""
        try:
            # ✅ SEMPRE ADICIONAR PRÓPRIA CHAVE PRIMEIRO!
            self.ring_keys = [self.public_key]
            
            # Obter todas as chaves públicas registadas da blockchain
            blockchain_keys = self.blockchain.get_all_user_keys()
            
            # Adicionar chaves da blockchain (evitando duplicação)
            self_key_bytes = serialize_key(self.public_key, is_private=False)
            seen_keys = {self_key_bytes}
            
            for key in blockchain_keys:
                key_bytes = serialize_key(key, is_private=False)
                if key_bytes not in seen_keys:  
                    self.ring_keys.append(key)
                    seen_keys.add(key_bytes)
            
            logger.info(f"Ring atualizado: {len(self.ring_keys)} chaves (incluindo própria)")
        
        except Exception as e:
            logger.error(f"Erro ao atualizar ring keys: {e}")
    
    def get_node_info(self):
        """Obter informações do node"""
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
        Obter ring keys para assinar (gera keys dummy se necessário)
        
        Ring signatures precisam de pelo menos 3 chaves.
        Se não houver chaves suficientes, gera keys dummy.
        
        Returns:
            list: Lista de chaves públicas serializadas
        """
        # Serializar todas as chaves do ring (já inclui própria chave!)
        existing_keys = [serialize_key(key, is_private=False) for key in self.ring_keys]
        
        # Se temos menos de 3 chaves, gerar dummies
        MIN_RING_SIZE = 3
        while len(existing_keys) < MIN_RING_SIZE:
            dummy_priv, dummy_pub = generate_keypair()
            dummy_pub_bytes = serialize_key(dummy_pub, is_private=False)
            existing_keys.append(dummy_pub_bytes)
            logger.warning(f"⚠️  Gerada chave dummy para ring (total: {len(existing_keys)}) - Ring muito pequeno!")
        
        logger.debug(f"Ring para assinar: {len(existing_keys)} chaves")
        return existing_keys

    def _get_username_from_pubkey(self, public_key_str):
        """Encontrar username atraves da chave publica"""
        
        user_txs = self.blockchain.get_transactions_by_type('USER_REGISTRATION')
        
        for tx in user_txs:
            if tx.get('public_key') == public_key_str:
                return tx.get('username', 'Unknown')
            
        return 'Unknown'
    
    def get_active_peers_count(self):
        """Contar apenas peers com sockets ativos"""
        
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
        """Remover sockets mortos da lista de peers"""
        
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
            logger.info(f"Removidos {removed_count} sockets mortos")


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
                "📢 Criar Leilão",
                "💰 Fazer Bid",
                "📋 Ver Leilões Ativos",
                "🏆 Meus Leilões (Seller)",
                "🔓 Fechar Leilão",
                "⛏️  Minerar Bloco",
                "🔗 Ver Blockchain",
                "👥 Ver Peers",
                "🔄 Atualizar",
                "❌ Sair"
            ]
            
            print_menu("MENU PRINCIPAL", options, width=60)
            
            choice = get_input("Escolhe uma opção", int, lambda x: 1 <= x <= len(options))
            
            if choice == 1:
                cli_create_auction(node)
            elif choice == 2:
                cli_submit_bid(node)
            elif choice == 3:
                cli_view_active_auctions(node)
            elif choice == 4:
                cli_view_my_auctions(node)
            elif choice == 5:
                cli_close_auction(node)
            elif choice == 6:
                cli_mine_block(node)
            elif choice == 7:
                cli_view_blockchain(node)
            elif choice == 8:
                cli_view_peers(node)
            elif choice == 9:
                continue  # Apenas refresh
            elif choice == 10:
                if get_confirmation("Tens a certeza que queres sair?"):
                    print_info("A encerrar node...")
                    break
        
        except KeyboardInterrupt:
            print("\n")
            if get_confirmation("Tens a certeza que queres sair?"):
                break
        except Exception as e:
            print_error(f"Erro: {e}")
            press_enter_to_continue()


# ========== CLI FUNCTIONS ====================



def cli_create_auction(node):
    """CLI: Criar leilão"""
    clear_screen()
    print_header("CRIAR LEILÃO")
    
    item = get_input("Descrição do item", str)
    reserve_price = get_input("Preço de reserva (€)", float, lambda x: x > 0)
    duration = get_input("Duração (minutos)", int, lambda x: x > 0)
    
    if get_confirmation("Confirmar criação do leilão?"):
        auction_id = node.create_auction(item, reserve_price, duration)
        if auction_id:
            print_success(f"Leilão criado com sucesso!")
            print_info(f"ID: {auction_id}")
    
    press_enter_to_continue()


def cli_submit_bid(node):
    """CLI: Submeter bid"""
    clear_screen()
    print_header("FAZER BID")
    
    # Mostrar leilões ativos
    auctions = node.get_active_auctions()
    if not auctions:
        print_warning("Não há leilões ativos no momento")
        press_enter_to_continue()
        return
    
    print("\nLeilões Ativos:")
    for i, auction in enumerate(auctions, 1):
        print(f"\n{i}. {auction.item_description}")
        print(f"   ID: {auction.auction_id}")
        print(f"   Termina: {format_timestamp(auction.end_time)}")
    
    idx = get_input(f"Escolhe leilão (1-{len(auctions)})", int, lambda x: 1 <= x <= len(auctions))
    auction = auctions[idx - 1]
    
    while True:
        bids = node.get_auction_bids(auction.auction_id)
        if bids:
            max_bid = max(bids, key = lambda b: b.bid_value)
            print(f"\n Maior bid atual: {max_bid.bid_value:.2f}€")
            print(f"Total de bids: {len(bids)}")
        else:
            print("\n Ainda nao ha bids neste leilao")
        
        bid_amount = get_input("\n Valor da tua bid (€) [0 para cancelar]", float, lambda x: x >= 0)
        
        if bid_amount == 0:
            print_info("Bid cancelada")
            break
        
        if get_confirmation(f"Confirmar bid de {bid_amount:.2f}€?"):
            success = node.submit_bid(auction.auction_id, bid_amount)
            
            if not success:
                if not get_confirmation("Quer tentar com outro valor?"):
                    break
                
            else:
                break
        
        else:
            if not get_confirmation("Quer tentar com outro valor?"):
                break
        
    press_enter_to_continue()
            


def cli_view_active_auctions(node):
    """CLI: Ver leilões ativos"""
    clear_screen()
    print_header("LEILÕES ATIVOS")
    
    auctions = node.get_active_auctions()
    server_time = node.get_server_time()
    
    if not auctions:
        print_warning("Não há leilões ativos no momento")
    else:
        for auction in auctions:
            
            status = node.auction_manager.get_auction_status(auction.auction_id, current_time = server_time)
            
            print_auction_details(auction, status)
            
            # Mostrar bids
            bids = node.get_auction_bids(auction.auction_id)
            if bids:
                print(f"\n  Bids ({len(bids)}):")
                for bid in sorted(bids, key=lambda b: b.bid_value, reverse=True):
                    print_bid_details(bid)
            print()
    
    press_enter_to_continue()


def cli_view_my_auctions(node):
    """CLI: Ver meus leilões (onde sou seller)"""
    clear_screen()
    print_header("MEUS LEILÕES")
    
    my_auctions = [aid for aid, secret in node.my_secrets.items() 
                if secret.get('type') == 'seller']
    
    if not my_auctions:
        print_warning("Não criaste nenhum leilão ainda")
    else:
        
        server_time = node.get_server_time()
        
        for auction_id in my_auctions:
            auction = node.auction_manager.get_auction(auction_id)
            if auction:
                
                status = node.auction_manager.get_auction_status(auction_id, current_time = server_time)
                
                print_auction_details(auction, status)
                
                bids = node.get_auction_bids(auction_id)
                print(f"  Total de bids: {len(bids)}")
                if bids:
                    max_bid = max(bids, key=lambda b: b.bid_value)
                    print(f"  Maior bid: {max_bid.bid_value:.2f}€")
                print()
    
    press_enter_to_continue()


def cli_close_auction(node):
    """CLI: Fechar leilão"""
    clear_screen()
    print_header("FECHAR LEILÃO")
    
    my_auctions = [aid for aid, secret in node.my_secrets.items() 
                if secret.get('type') == 'seller']
    
    if not my_auctions:
        print_warning("Não tens leilões para fechar")
        press_enter_to_continue()
        return
    
    server_time = node.get_server_time()
    
    print("\nMeus Leilões:")
    for i, auction_id in enumerate(my_auctions, 1):
        auction = node.auction_manager.get_auction(auction_id)
        if auction:
            status = node.auction_manager.get_auction_status(auction_id, current_time = server_time)
            print(f"\n{i}. {auction.item_description} ({auction_id})")
            print(f"   Status: {status.value}")
    
    idx = get_input(f"Escolhe leilão (1-{len(my_auctions)})", int, lambda x: 1 <= x <= len(my_auctions))
    auction_id = my_auctions[idx - 1]
    
    if get_confirmation("Fechar e determinar vencedor?"):
        node.close_and_finalize_auction(auction_id)
    
    press_enter_to_continue()


def cli_mine_block(node):
    """CLI: Minerar bloco"""
    clear_screen()
    print_header("MINERAR BLOCO")
    
    print_info(f"Transações pendentes: {len(node.blockchain.pending_transactions)}")
    
    if node.blockchain.pending_transactions:
        if get_confirmation("Minerar bloco agora?"):
            print_progress("Minerando...", 2)
            node.mine_block()
    else:
        print_warning("Não há transações pendentes")
    
    press_enter_to_continue()


def cli_view_blockchain(node):
    """CLI: Ver blockchain"""
    clear_screen()
    print_header("BLOCKCHAIN")
    
    print_info(f"Total de blocos: {len(node.blockchain.chain)}")
    print_info(f"Último hash: {node.blockchain.get_last_block_hash()[:32]}...")
    
    if get_confirmation("Ver detalhes dos blocos?"):
        for block in node.blockchain.chain[-5:]:  # Últimos 5
            print(f"\nBloco #{block.index}")
            print(f"  Hash: {block.hash[:32]}...")
            print(f"  Transações: {len(block.transactions)}")
            print(f"  Timestamp: {format_timestamp(block.timestamp)}")
    
    press_enter_to_continue()


def cli_view_peers(node):
    """CLI: Ver peers"""
    clear_screen()
    print_header("PEERS CONECTADOS")
    
    active_peers = node.get_active_peers_count()
    
    print_info(f"Peers conectados (aticos): {active_peers}")
    print_info(f"Ring size: {len(node.ring_keys)}")
    
    if active_peers < len(node.ring_keys) - 1:
        print_warning(f"Alguns users estão offline ({len(node.ring_keys - 1 - active_peers )} offline)")
    
    press_enter_to_continue()


# ========== MAIN ==========
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python node.py <username> [porta]")
        print("Exemplo: python node.py Alice 8000")
        sys.exit(1)
    
    username = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    # Criar e iniciar node
    node = AuctionNode(username, p2p_port=port)
    node.start()
    
    # Executar CLI
    try:
        run_cli(node)
    except KeyboardInterrupt:
        print("\n")
    finally:
        print_info(f"Node {username} encerrado")