from flask import Flask, request, jsonify
import time
import sys
import os
import ssl

# Adicionar path para importar crypto_utils
client_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'client')
sys.path.insert(0, client_dir)

from crypto_utils import generate_keypair, sign_data, serialize_key

app = Flask(__name__)

peers = {}           
registered_users = {}
timestamps = []      
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_keypair()
SERVER_PUBLIC_KEY_BYTES = serialize_key(SERVER_PUBLIC_KEY, is_private=False)



@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'ok', 'timestamp': time.time()})


@app.route('/register', methods=['POST'])
def register_user():
    """Register user in system"""
    data = request.json
    username = data.get('username')
    public_key = data.get('public_key')
    
    if not username or not public_key:
        return jsonify({'error': 'username e public_key obrigatórios'}), 400
    
    registered_users[username] = public_key
    
    return jsonify({
        'status': 'ok',
        'message': f'User {username} registado',
        'total_users': len(registered_users)
    })

@app.route('/lookup_username', methods=['POST'])
def lookup_username():
    """Lookup username por public key"""
    data = request.json
    public_key = data.get('public_key')
    
    if not public_key:
        return jsonify({'error': 'public_key obrigatoria'}), 400
    
    for username, pk in registered_users.items():
        if pk == public_key:
            return jsonify({'username': username})
    
    return jsonify({'username': None}), 404

@app.route('/lookup_pubkey', methods=['POST'])
def lookup_pubkey():
    """Lookup pubkey por username"""
    
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'username obrigatorio'}), 400
    
    public_key = registered_users.get(username)
    
    if public_key:
        return jsonify({'public_key': public_key})
    
    return jsonify({'public_key': None}), 404

@app.route('/users/public_keys', methods=['GET'])
def get_public_keys():
    """Obtain all public keys"""
    return jsonify({
        'public_keys': list(registered_users.values()),
        'count': len(registered_users)
    })


@app.route('/peers/announce', methods=['POST'])
def announce_peer():
    """Peer anuncia presença"""
    data = request.json
    peer_id = data.get('peer_id')
    port = data.get('port')
    
    if not peer_id or not port:
        return jsonify({'error': 'peer_id e port obrigatórios'}), 400
    
    peers[peer_id] = {
        'ip': request.remote_addr,
        'port': port,
        'last_seen': time.time()
    }
    
    return jsonify({
        'status': 'ok',
        'peer_count': len(peers)
    })


@app.route('/peers/list', methods=['GET'])
def list_peers():
    """Obtain list of active peers"""
    now = time.time()
    active_peers = {
        pid: info for pid, info in peers.items()
        if now - info['last_seen'] < 300  
    }
    
    return jsonify({
        'peers': list(active_peers.values()),
        'count': len(active_peers)
    })


@app.route('/timestamp', methods=['POST'])
def timestamp_service():
    """Trusted timestamp service"""
    data = request.json
    data_hash = data.get('hash')
    
    if not data_hash:
        return jsonify({'error': 'hash obrigatório'}), 400
    
    # Create timestamp
    ts = time.time()
    
    # Sign
    message = f"{data_hash}:{ts}"
    signature = sign_data(message, SERVER_PRIVATE_KEY)
    
    # Store
    timestamps.append({
        'hash': data_hash,
        'timestamp': ts,
        'signature': signature.hex()  
    })
    
    return jsonify({
        'timestamp': ts,
        'signature': signature.hex(),
        'server_pubkey': SERVER_PUBLIC_KEY_BYTES.decode('utf-8')
    })


@app.route('/timestamp/verify', methods=['POST'])
def verify_timestamp():
    """Verify if timestamp was issued by server"""
    data = request.json
    
    record = next(
        (t for t in timestamps 
        if t['hash'] == data.get('hash') and t['timestamp'] == data.get('timestamp')),
        None
    )
    
    if record:
        return jsonify({'valid': True, 'timestamp': record['timestamp']})
    
    return jsonify({'valid': False})


@app.route('/stats', methods=['GET'])
def stats():
    """Server stats"""
    return jsonify({
        'registered_users': len(registered_users),
        'active_peers': len([p for p in peers.values() if time.time() - p['last_seen'] < 300]),
        'timestamps_issued': len(timestamps),
        'uptime': time.time()  
    })
    


# ========== INICIAR SERVIDOR ==========
if __name__ == '__main__':
    print("=" * 50)
    print("🚀 Servidor de Leilão P2P")
    print("=" * 50)
    print(f"📡 Endpoints disponíveis:")
    print(f"  - GET  /health")
    print(f"  - POST /register")
    print(f"  - GET  /users/public_keys")
    print(f"  - POST /peers/announce")
    print(f"  - GET  /peers/list")
    print(f"  - POST /timestamp")
    print(f"  - POST /timestamp/verify")
    print(f"  - GET  /stats")
    print("=" * 50)
    
    
    cert_file = 'server_cert.pem'
    key_file = 'server_key.pem'
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file, key_file)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        ssl_context = None
        print("ERRO: TLS DESATIVADO")
    
    app.run(
        host='0.0.0.0',  
        port=5001,
        debug=True,
        ssl_context = ssl_context
    )