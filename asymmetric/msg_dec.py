
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


password = b"mypassword" 

with open("./key/private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=password,
    )


with open( "./message.encrypted.txt", 'rb') as ciphertext:
    plaintext = private_key.decrypt(
        ciphertext.read(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open( "./message.decrypred.txt", 'wb') as decrypted_msg:
        decrypted_msg.write(plaintext)
