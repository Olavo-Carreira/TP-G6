from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import hashlib
import json
import os

def generate_keypair():
    """Gerar par de chaves RSA"""
    
    private_key = rsa.generate_private_key(
        public_exponent = 65537, #Padrao RSA numero primo
        key_size = 2048,
        backend = default_backend()
    )
    
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key, is_private = False):
    """Converter chave para bytes (para envio)"""
    
    if is_private:
        return key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption() #sem pass
        )
    else:
        return key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

def deserialize_key(key_bytes, is_private=False):
    """Converter bytes de volta para chave"""
    
    if is_private:
        return serialization.load_pem_private_key(
            key_bytes,
            password = None,
            backend = default_backend()
        )
    else:
        return serialization.load_pem_public_key(
            key_bytes,
            backend = default_backend()
        )

def hash_data(data):
    """SHA 256 de dados"""
    
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()
    
def sign_data(data, private_key):
    """Assinar dados com chave privada"""

    if isinstance(data,str):
        data = data.encode()
        
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

def verify_signature(data, signature, public_key):
    """Verificar assinatura com chave pública"""
    
    if isinstance(data, str):
        data = data.encode()
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
    
def encrypt_for_dest(message, dest_pubkey):
    """Encriptar mensagem -> AES para dados q é sem limites e RSA para chave AES"""
    
    if isinstance(message, dict):
        message = json.dumps(message)
    
    if isinstance(message, str):
        message = message.encode()
    
    aes_key = os.urandom(32)
    
    nonce = os.urandom(12)
    
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(message) + encryptor.finalize()
    
    encrypted_aes_key = dest_pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    
    return {
        'encrypted_key': encrypted_aes_key.hex(),
        'encrypted_data': encrypted_data.hex(),
        'tag': encryptor.tag.hex(),
        'nonce': nonce.hex()
    }

def decryprt_from_dest(encrypted_message, prvkey):
    """Desencriptar mensagem recebida"""
    
    try:
        
        encrypted_aes_key = bytes.fromhex(encrypted_message['encrypted_key'])
        encrypted_data = bytes.fromhex(encrypted_message['encrypted_data'])
        tag = bytes.fromhex(encrypted_message['tag'])
        nonce = bytes.fromhex(encrypted_message['nonce'])
        
        aes_key = prvkey.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
            )
        )
        
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce,tag),
            backend=default_backend
        )
        
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        try:
            return json.loads(decrypted_data.decode())
        except:
            return decrypted_data.decode()
    
    except Exception:
        return None