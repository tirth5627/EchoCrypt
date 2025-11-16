🎵🔐 EchoCrypt

Secure Audio Steganography using Diffie–Hellman Key Exchange + AES-GCM Encryption

EchoCrypt is a hybrid cryptography + steganography system that securely hides encrypted data inside WAV audio files.
It ensures safe and covert communication by combining:

Elliptic Curve Diffie–Hellman (ECDH) for dynamic key exchange

AES-256 GCM for authenticated encryption

LSB Audio Steganography for invisible data embedding

WAV PCM manipulation for lossless bit-level control

EchoCrypt allows encrypted data to be seamlessly embedded inside audio in a way that remains undetectable to both listeners and standard analysis tools.

🚀 Features

✔ Hide any text file inside a WAV audio
✔ AES-256-GCM ensures confidentiality + tamper detection
✔ ECDH key exchange eliminates the need to share private keys
✔ Human-imperceptible audio modification using LSB technique
✔ Clean, modular, and academic-grade Python implementation
✔ Perfect for cybersecurity, steganography, and cryptographic applications

🛠️ Technology Stack
Component	Purpose
Python	Core implementation
cryptography	AES-GCM + ECDH key exchange
wave module	Handling WAV audio data
LSB Steganography	Embedding encrypted payload
📁 Project Structure
EchoCrypt/
├── audio_steg.py         # Core cryptography + steganography logic
├── make_keys.py          # Generates ECDH key pair (receiver)
├── sender.py             # Encrypts + embeds secret into WAV
├── receiver.py           # Extracts + decrypts from WAV
├── clean.wav             # Carrier audio
├── secret.txt            # File to hide
├── hidden.wav            # Output with hidden encrypted content
├── receiver_pub.pem      # Receiver public key
├── receiver_priv.pem     # Receiver private key
└── README.md

🔧 Installation
Install required library
pip install cryptography

Optional (if you want to convert MP3 → WAV)
sudo apt install ffmpeg

🔑 1. Generate Receiver Key Pair

Run:

python make_keys.py


This will generate:

receiver_pub.pem

receiver_priv.pem

The public key is shared with the sender.
The private key remains secret with the receiver.

🎧 2. Prepare the Audio

You must use a WAV audio file.

To convert an MP3:

ffmpeg -i input.mp3 clean.wav


Or use any existing .wav file.

📝 3. Create the Secret File

Example:

echo "Hidden message inside audio!" > secret.txt

🔐 4. Encrypt + Embed Inside Audio

Run:

python sender.py


This creates:

hidden.wav


This file contains the encrypted + hidden data.

🔓 5. Extract + Decrypt the Hidden File

Run:

python receiver.py


Output:

recovered.txt


This is the decrypted version of the original secret file.

🧠 How EchoCrypt Works (Technical Overview)
1️⃣ Elliptic Curve Diffie–Hellman (ECDH)

Sender creates an ephemeral ECC key pair

Receiver has a long-term ECC key pair

Both sides compute a shared secret:

shared_secret = sender_private.exchange(ECDH(), receiver_public)


The shared secret is processed with HKDF to derive:

256-bit AES key

2️⃣ AES-256-GCM Encryption

EchoCrypt encrypts the secret data using:

AES-GCM (provides confidentiality + authentication)

A random 96-bit nonce

Ciphertext integrity is guaranteed via GCM tag

3️⃣ LSB Audio Steganography

Encrypted payload bytes are embedded into the least significant bits of WAV samples.

Payload format:

[4 bytes]  sender_public_key_length
[N bytes]  sender_public_key
[4 bytes]  ciphertext_length
[12 bytes] nonce
[X bytes]  ciphertext

4️⃣ Extraction & Decryption

The receiver:

Reads the hidden payload from the WAV

Reconstructs the keys & ciphertext

Recomputes the shared secret

Decrypts data using AES-GCM

Recovers the original file as recovered.txt

👨‍💻 Authors

Tirth Patel (U23AI072)
Het Talavia (U23AI077)

Artificial Intelligence Department
Sardar Vallabhbhai National Institute of Technology (SVNIT)

