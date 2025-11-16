from audio_steg import generate_ecdh_keypair
from cryptography.hazmat.primitives import serialization

# Generate ECDH keys
priv, pub = generate_ecdh_keypair()

# Save private key
with open("receiver_priv.pem", "wb") as f:
    f.write(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )

# Save public key
with open("receiver_pub.pem", "wb") as f:
    f.write(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Keys generated:\n - receiver_priv.pem\n - receiver_pub.pem")
