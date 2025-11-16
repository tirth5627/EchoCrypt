from audio_steg import sender_encrypt_and_embed

sender_encrypt_and_embed(
    input_wav="clean.wav",
    textfile="secret.txt",
    receiver_pub_file="receiver_pub.pem",
    output_wav="hidden.wav"
)
