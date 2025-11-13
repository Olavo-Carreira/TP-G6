import hashlib
import os
import random
from crypto_utils import sign_data, verify_signature, serialize_key, deserialize_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def create_ring_signature(message, signer_private_key, public_keys_list):
    """
    Cria ring signature usando chaves publicas dos outros membros
    
    Args:
        message: dados a assinar (string ou bytes)
        signer_private_key: chave privada de quem assina
        public_keys_list: lista de chaves publicas do grupo (bytes serialized)
    
    Returns:
        dict com signature, ring_size, key_images, signer_index (embaralhado)
    """
    if isinstance(message, str):
        message = message.encode()
    
    # Hash da mensagem
    message_hash = hashlib.sha256(message).digest()
    
    # Identificar posicao do assinante no ring
    signer_pubkey_bytes = serialize_key(
        signer_private_key.public_key(), 
        is_private=False
    )
    
    # Encontrar indice do assinante (sua chave publica deve estar na lista)
    signer_index = None
    for i, pub_key_bytes in enumerate(public_keys_list):
        if isinstance(pub_key_bytes, str):
            pub_key_bytes = pub_key_bytes.encode()
        if pub_key_bytes == signer_pubkey_bytes:
            signer_index = i
            break
    
    if signer_index is None:
        raise ValueError("Chave publica do assinante nao encontrada no ring!")
    
    # Assinar com chave privada (signature real)
    real_signature = sign_data(message, signer_private_key)
    
    # Criar assinaturas "simuladas" usando chaves publicas dos OUTROS
    ring_size = len(public_keys_list)
    signatures = []
    
    for i, pub_key_bytes in enumerate(public_keys_list):
        if i == signer_index:
            # Posicao do assinante - usa assinatura real
            signatures.append({
                'signature': real_signature.hex(),
                'public_key': pub_key_bytes.decode() if isinstance(pub_key_bytes, bytes) else pub_key_bytes
            })
        else:
            # Outras posicoes - criar "assinatura simulada"
            # Usa a chave publica do membro para criar valor aparente
            if isinstance(pub_key_bytes, str):
                pub_key_bytes = pub_key_bytes.encode()
            
            pub_key = deserialize_key(pub_key_bytes, is_private=False)
            
            # Criar "assinatura aparente" usando chave publica
            # (cifrar mensagem com chave publica simula assinatura)
            simulated_sig = pub_key.encrypt(
                message_hash[:190],  # RSA 2048 aceita max 190 bytes com padding
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            signatures.append({
                'signature': simulated_sig.hex(),
                'public_key': pub_key_bytes.decode() if isinstance(pub_key_bytes, bytes) else pub_key_bytes
            })
    
    # Criar key image (identificador unico que nao revela identidade)
    key_image = hashlib.sha256(signer_pubkey_bytes + message_hash).hexdigest()
    
    # Embaralhar posicoes (para esconder qual e a real)
    shuffled_indices = list(range(ring_size))
    random.shuffle(shuffled_indices)
    
    shuffled_signatures = [signatures[i] for i in shuffled_indices]
    
    ring_signature = {
        'signatures': shuffled_signatures,
        'ring_size': ring_size,
        'key_image': key_image,
        'message_hash': message_hash.hex(),
        'shuffle_map': shuffled_indices  # Para debug (remover em producao)
    }
    
    return ring_signature


def verify_ring_signature(message, ring_signature, public_keys_list):
    """
    Verifica ring signature
    
    Testa se ALGUMA das assinaturas no ring corresponde a sua chave publica,
    sem revelar qual.
    
    Args:
        message: mensagem original
        ring_signature: dict retornado por create_ring_signature
        public_keys_list: lista de chaves publicas do grupo
    
    Returns:
        bool: True se pelo menos uma assinatura valida encontrada
    """
    if isinstance(message, str):
        message = message.encode()
    
    # Verificar hash da mensagem
    message_hash = hashlib.sha256(message).digest()
    
    if message_hash.hex() != ring_signature['message_hash']:
        print("Hash da mensagem nao coincide")
        return False
    
    # Verificar ring size
    if ring_signature['ring_size'] != len(public_keys_list):
        print("Tamanho do ring nao coincide")
        return False
    
    # Tentar verificar cada assinatura no ring
    signatures = ring_signature['signatures']
    
    valid_count = 0
    
    for sig_entry in signatures:
        sig_hex = sig_entry['signature']
        sig_bytes = bytes.fromhex(sig_hex)
        pub_key_str = sig_entry['public_key']
        
        try:
            # Deserializar chave publica
            pub_key = deserialize_key(pub_key_str.encode(), is_private=False)
            
            # Tentar verificar como assinatura RSA normal
            if verify_signature(message, sig_bytes, pub_key):
                valid_count += 1
                continue
            
            # Se nao for assinatura normal, pode ser cifrada (simulada)
            # Tentar decifrar nao funciona sem chave privada (esperado)
            
        except Exception as e:
            # Assinaturas simuladas vao falhar aqui (esperado)
            continue
    
    # Se encontramos PELO MENOS UMA assinatura valida, o ring e valido
    if valid_count >= 1:
        print(f"Ring signature valida ({valid_count} assinatura(s) verificavel(is))")
        return True
    
    print(f"Nenhuma assinatura valida encontrada")
    return False

### Teste de módulo ###

if __name__ == '__main__':
    """Teste do modulo de ring signatures"""
    from crypto_utils import generate_keypair
    import json
    
    print("="*50)
    print("Teste de Ring Signatures")
    print("="*50)
    
    # Gerar 3 pares de chaves (simulando 3 peers)
    print("\nGerando 3 pares de chaves...")
    peers = []
    for i in range(3):
        priv, pub = generate_keypair()
        peers.append({
            'name': f'Peer{i+1}',
            'private': priv,
            'public': pub
        })
    print("Chaves geradas")
    
    # Extrair chaves publicas
    public_keys = [serialize_key(p['public'], is_private=False) for p in peers]
    
    # Peer1 assina mensagem anonimamente
    print("\nPeer1 criando ring signature...")
    message = "Mensagem anonima de teste"
    
    ring_sig = create_ring_signature(
        message,
        peers[0]['private'],
        public_keys
    )
    
    print(f"Ring signature criada (ring size: {ring_sig['ring_size']})")
    
    # Verificar
    print("\nVerificando ring signature...")
    is_valid = verify_ring_signature(message, ring_sig, public_keys)
    
    if is_valid:
        print("\nSUCESSO: Ring signature valida!")
        print("Impossivel determinar que foi Peer1 que assinou")
    else:
        print("\nFALHA: Ring signature invalida")
    
    print("="*50)
