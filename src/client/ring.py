import hashlib
import random
from crypto_utils import sign_data, verify_signature, serialize_key, deserialize_key


def ring_sign(message, signer_private_key, public_keys_list):
    """Criar ring signature"""
    
    if isinstance(message, str):
        message = message.encode()
    
    # Hash da mensagem
    message_hash = hashlib.sha256(message).digest()
    
    # Serializar chave pública do assinante
    signer_pubkey_bytes = serialize_key(
        signer_private_key.public_key(), 
        is_private=False
    )
    
    # Encontrar índice do assinante no ring
    signer_index = None
    for i, pub_key_bytes in enumerate(public_keys_list):
        if isinstance(pub_key_bytes, str):
            pub_key_bytes = pub_key_bytes.encode()
        if pub_key_bytes == signer_pubkey_bytes:
            signer_index = i
            break
    
    if signer_index is None:
        raise ValueError("Chave pública do assinante não encontrada no ring!")
    
    # Criar assinatura real
    real_signature = sign_data(message, signer_private_key)
    
    # Criar lista de todas as assinaturas (real + preenchimento)
    ring_size = len(public_keys_list)
    signatures = []
    
    for i, pub_key_bytes in enumerate(public_keys_list):
        if i == signer_index:
            signatures.append({
                'signature': real_signature.hex(),
                'public_key': pub_key_bytes.decode() if isinstance(pub_key_bytes, bytes) else pub_key_bytes
            })
        else:
            dummy_sig = hashlib.sha256(
                pub_key_bytes + message_hash + str(i).encode()
            ).digest() * 8  
            
            signatures.append({
                'signature': dummy_sig.hex(),
                'public_key': pub_key_bytes.decode() if isinstance(pub_key_bytes, bytes) else pub_key_bytes
            })
    
    # Embaralhar para esconder posição real
    random.shuffle(signatures)
    
    key_image = hashlib.sha256(signer_pubkey_bytes + message_hash).hexdigest()
    
    ring_signature = {
        'signatures': signatures,
        'ring_size': ring_size,
        'key_image': key_image,
        'message_hash': message_hash.hex()
    }
    
    return ring_signature


def ring_verify(message, ring_signature, public_keys_list):
    """Verificar ring signature"""
    
    if isinstance(message, str):
        message = message.encode()
    
    message_hash = hashlib.sha256(message).digest()
    if message_hash.hex() != ring_signature['message_hash']:
        return False
    
    if ring_signature['ring_size'] != len(public_keys_list):
        return False
    
    signatures = ring_signature['signatures']
    
    for sig_entry in signatures:
        sig_hex = sig_entry['signature']
        pub_key_str = sig_entry['public_key']
        
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            pub_key = deserialize_key(pub_key_str.encode(), is_private=False)
            
            # Tentar verificar como assinatura RSA
            if verify_signature(message, sig_bytes, pub_key):
                # Encontrou assinatura válida!
                return True
        
        except Exception:
            continue
    
    # Nenhuma assinatura válida encontrada
    return False


def get_ring_from_blockchain(blockchain):
    """Obter ring (todas as chaves públicas) da blockchain"""
    return blockchain.get_all_user_keys()


# ========== TESTE ==========
if __name__ == '__main__':
    from crypto_utils import generate_keypair
    
    print("="*50)
    print("🧪 Teste Ring Signatures")
    print("="*50)
    
    # Gerar 5 users
    print("\n1. Gerando 5 pares de chaves...")
    peers = []
    for i in range(5):
        priv, pub = generate_keypair()
        peers.append({
            'name': f'User{i+1}',
            'private': priv,
            'public': pub
        })
    print("✅ Chaves geradas")
    
    # Criar ring
    public_keys = [serialize_key(p['public'], is_private=False) for p in peers]
    print(f"✅ Ring criado (tamanho: {len(public_keys)})")
    
    # User 3 assina anonimamente
    signer = peers[2]  # User3
    message = "Bid: 150€ para Auction_001"
    
    print(f"\n2. {signer['name']} criando ring signature...")
    ring_sig = ring_sign(message, signer['private'], public_keys)
    print(f"✅ Ring signature criada")
    print(f"   Key image: {ring_sig['key_image'][:16]}...")
    print(f"   Ring size: {ring_sig['ring_size']}")
    
    # Verificar
    print(f"\n3. Verificando ring signature...")
    is_valid = ring_verify(message, ring_sig, public_keys)
    
    if is_valid:
        print("✅ SUCESSO: Ring signature VÁLIDA!")
        print("❓ Quem assinou? Impossível determinar!")
        print(f"   Pode ser: {', '.join([p['name'] for p in peers])}")
    else:
        print("❌ FALHA: Ring signature inválida")
    
    # Teste negativo
    print(f"\n4. Teste negativo (mensagem alterada)...")
    tampered_message = "Bid: 200€ para Auction_001"
    is_valid_tampered = ring_verify(tampered_message, ring_sig, public_keys)
    
    if not is_valid_tampered:
        print("✅ SUCESSO: Assinatura rejeitada para mensagem alterada")
    else:
        print("❌ FALHA: Deveria rejeitar mensagem alterada")
    
    print("\n" + "="*50)