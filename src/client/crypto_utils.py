from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

import hashlib

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
    
if __name__ == '__main__':
    # Gerar chaves
    priv, pub = generate_keypair()
    print("✅ Chaves geradas")
    
    # Serializar
    priv_bytes = serialize_key(priv, is_private=True)
    pub_bytes = serialize_key(pub, is_private=False)
    print("✅ Chaves serializadas")
    
    # Deserializar
    priv2 = deserialize_key(priv_bytes, is_private=True)
    pub2 = deserialize_key(pub_bytes, is_private=False)
    print("✅ Chaves desserializadas")
    
    # Assinar
    message = "Test message"
    sig = sign_data(message, priv)
    print("✅ Dados assinados")
    
    # Verificar
    valid = verify_signature(message, sig, pub)
    print(f"✅ Verificação: {valid}")
    
    # Hash
    h = hash_data(message)
    print(f"✅ Hash: {h[:16]}...")