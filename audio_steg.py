import wave, os, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


# --- Utility: ECDH Key Generation ---
def generate_ecdh_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())  # You can use X25519 also
    pub = priv.public_key()
    return priv, pub


def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"audio-dh-steg"
    ).derive(shared_secret)


# --- AES Encryption ---
def aes_encrypt(key, data):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, data, None)
    return nonce, ciphertext


def aes_decrypt(key, nonce, ciphertext):
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


# --- WAV LSB Steganography ---
def hide_bytes_in_wav(input_wav, output_wav, payload):
    with wave.open(input_wav, "rb") as w:
        params = w.getparams()
        frames = bytearray(w.readframes(w.getnframes()))

    if len(payload) * 8 > len(frames):
        raise ValueError("Audio file too small!")

    index = 0
    for byte in payload:
        for bit in range(8):
            frames[index] &= 0xFE
            frames[index] |= (byte >> bit) & 1
            index += 1

    with wave.open(output_wav, "wb") as w:
        w.setparams(params)
        w.writeframes(frames)

    print("[+] Hidden data inside audio:", output_wav)


def extract_bytes_from_wav(stego_wav, length):
    with wave.open(stego_wav, "rb") as w:
        frames = bytearray(w.readframes(w.getnframes()))

    data = bytearray()
    index = 0
    for _ in range(length):
        byte = 0
        for bit in range(8):
            byte |= (frames[index] & 1) << bit
            index += 1
        data.append(byte)

    return bytes(data)


# --- Main Functions ---

def sender_encrypt_and_embed(input_wav, textfile, receiver_pub_file, output_wav):
    # Load receiver public key
    with open(receiver_pub_file, "rb") as f:
        receiver_pub = serialization.load_pem_public_key(f.read())

    # Sender creates ephemeral DH key
    sender_priv, sender_pub = generate_ecdh_keypair()
    sender_pub_bytes = sender_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Compute shared secret
    shared_secret = sender_priv.exchange(ec.ECDH(), receiver_pub)
    key = derive_key(shared_secret)

    # Encrypt text file
    data = open(textfile, "rb").read()
    nonce, ciphertext = aes_encrypt(key, data)

    # Final payload format:
    payload = (
    struct.pack(">I", len(sender_pub_bytes)) + 
    sender_pub_bytes +
    struct.pack(">I", len(ciphertext)) +   # NEW LINE
    nonce +
    ciphertext
    )


    hide_bytes_in_wav(input_wav, output_wav, payload)
    print("[+] Sender public key length:", len(sender_pub_bytes))
    print("[+] Payload size:", len(payload))

def receiver_extract_and_decrypt(stego_wav, receiver_priv_file, output_file):
    # Load receiver private key
    with open(receiver_priv_file, "rb") as f:
        receiver_priv = serialization.load_pem_private_key(f.read(), None)

    # --- Step 1: Read sender_pub_len ---
    prefix = extract_bytes_from_wav(stego_wav, 4)
    (sender_pub_len,) = struct.unpack(">I", prefix)

    # --- Step 2: Read sender public key ---
    temp = extract_bytes_from_wav(stego_wav, 4 + sender_pub_len)
    sender_pub_bytes = temp[4:]
    sender_pub = serialization.load_pem_public_key(sender_pub_bytes)

    # --- Step 3: Read ciphertext length ---
    temp = extract_bytes_from_wav(stego_wav, 4 + sender_pub_len + 4)
    ciphertext_len = struct.unpack(">I", temp[-4:])[0]

    # TOTAL PAYLOAD SIZE =
    # 4 (pub_len) + pub_len + 4 (cipher_len) + 12 (nonce) + ciphertext_len

    total_size = 4 + sender_pub_len + 4 + 12 + ciphertext_len

    # --- Step 4: Extract full payload ---
    full_payload = extract_bytes_from_wav(stego_wav, total_size)

    # Parse pieces
    offset = 0
    sender_pub_len = struct.unpack(">I", full_payload[0:4])[0]
    offset = 4 + sender_pub_len

    ciphertext_len = struct.unpack(">I", full_payload[offset:offset+4])[0]
    offset += 4

    nonce = full_payload[offset:offset+12]
    offset += 12

    ciphertext = full_payload[offset:offset + ciphertext_len]

    # --- Step 5: Derive shared secret ---
    shared_secret = receiver_priv.exchange(ec.ECDH(), sender_pub)
    key = derive_key(shared_secret)

    # --- Step 6: Decrypt safely ---
    plaintext = aes_decrypt(key, nonce, ciphertext)

    with open(output_file, "wb") as f:
        f.write(plaintext)

    print("[+] Decrypted successfully:", output_file)
