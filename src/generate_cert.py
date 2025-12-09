from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress
import os


# Generate privte key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Define subject 
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Braga"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auction System"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

# Create certificate
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    )
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    .sign(private_key, hashes.SHA256())
)

# Store private key
with open("server_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

os.chmod("server_key.pem", 0o600)

# Store certificate 
with open("server_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

