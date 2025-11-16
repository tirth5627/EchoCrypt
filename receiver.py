from audio_steg import receiver_extract_and_decrypt

receiver_extract_and_decrypt(
    stego_wav="hidden.wav",
    receiver_priv_file="receiver_priv.pem",
    output_file="recovered.txt"
)
