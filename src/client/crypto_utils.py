from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import hashlib
import json
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def generate_keypair():
    """Generate RSA keypair"""
    
    private_key = rsa.generate_private_key(
        public_exponent = 65537, # RSA standard prime number
        key_size = 2048,
        backend = default_backend()
    )
    
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key, is_private = False):
    """Convert key to bytes (for sending)"""
    
    if is_private:
        return key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption() # no password
        )
    else:
        return key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

def deserialize_key(key_bytes, is_private=False):
    """Convert bytes back to key"""
    
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
    """SHA256 of data"""
    
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()
    
def sign_data(data, private_key):
    """Sign data with private key"""

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
    """Verify signature with public key"""
    
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
    """Encrypt message -> AES for data (no limits) and RSA for AES key"""
    
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
    """Decrypt received message"""
    
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
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        try:
            return json.loads(decrypted_data.decode())
        except:
            return decrypted_data.decode()
    
    except Exception:
        return None

def get_user_data_dir(username):
    """Get user-specific data directory"""
    home = Path.home()
    user_dir = home / '.auction_system' / username.lower()
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


def derive_key_from_password(password, salt):
    """Derive encryption key from password using PBKDF2"""
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt,
        iterations=100000,  
        backend=default_backend()
    )
    
    return kdf.derive(password.encode('utf-8'))


def encrypt_private_key_with_password(private_key, password):
    """Encrypt private key with password-derived AES key"""
    # Generate random salt
    salt = os.urandom(16)
    
    # Derive AES key from password
    aes_key = derive_key_from_password(password, salt)
    
    # Serialize private key
    priv_pem = serialize_key(private_key, is_private=True)
    
    # Encrypt with AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(priv_pem) + encryptor.finalize()
    
    return {
        'salt': salt.hex(),
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': encryptor.tag.hex()
    }


def decrypt_private_key_with_password(encrypted_data, password):
    """Decrypt private key with password"""
    try:
        # Parse encrypted data
        salt = bytes.fromhex(encrypted_data['salt'])
        nonce = bytes.fromhex(encrypted_data['nonce'])
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
        tag = bytes.fromhex(encrypted_data['tag'])
        
        # Derive AES key from password
        aes_key = derive_key_from_password(password, salt)
        
        # Decrypt with AES-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        priv_pem = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Deserialize private key
        private_key = deserialize_key(priv_pem, is_private=True)
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    except Exception as e:
        return None


def save_keypair(username, private_key, public_key, password):
    """Save keypair to disk with password protection"""
    user_dir = get_user_data_dir(username)
    
    # Encrypt with password
    encrypted_data = encrypt_private_key_with_password(private_key, password)
    
    secure_file = user_dir / 'keypair.json'
    secure_file.write_text(json.dumps(encrypted_data, indent=2))
    
    try:
        secure_file.chmod(0o600)
    except Exception as e:
        logger.warning(f"Could not set file permissions: {e}")
    


def load_keypair(username, password):
    """Load keypair from disk with password"""
    user_dir = get_user_data_dir(username)
    secure_file = user_dir / 'keypair.json'
    
    if not secure_file.exists():
        logger.debug(f"No saved keypair found for {username}")
        return None
    
    try:
        encrypted_data = json.loads(secure_file.read_text())
        keys = decrypt_private_key_with_password(encrypted_data, password)
        
        return keys
    
    except Exception as e:
        logger.error(f"Error loading encrypted keypair: {e}")
        return None


def keypair_exists(username):
    """Check if keypair exists for user"""
    user_dir = get_user_data_dir(username)
    return (user_dir / 'keypair.json').exists()