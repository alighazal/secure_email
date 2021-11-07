from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


message = b"Hello World, My name is Ali Ghazal"

with open("./key/public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
    )


message =  open( "./message.txt", 'rb').read()


ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

with open( "./message.encrypted.txt", 'wb') as encrypted_msg:
    encrypted_msg.write(ciphertext)

