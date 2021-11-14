from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


#import hashlib 

from cryptography.hazmat.primitives import hashes


import server

import json

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_message_with_AES(message, key):
    print("-->encrypt_message_with_AES")
    #encrypt the message digest with the message to verify integrity
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)

    message_digest = digest.finalize()

    print ("hash --> ", message_digest )

    with open( "./message.hash.txt", 'wb') as hashed_msg:
        hashed_msg.write(message_digest)

    f = Fernet(key)
   
    ## TODO { Message + hash } in one file
    ## TODO handle hash

    encrypted_message = f.encrypt( message ) 
    return encrypted_message

def lookup_public_key_by_email(conn, recipient_email):
    print("-->lookup_public_key_by_email")
    reciepient_public_key = server.select_user_by_email(conn, recipient_email)
    public_key = serialization.load_pem_public_key(
        reciepient_public_key,
    )
    return public_key

def encrypt_message_key_with_RSA(message_key, key):
    print("-->encrypt_message_key_with_RSA")
    encrypted_key = key.encrypt(
        message_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key

def sign_message(encrypted_message, encrypted_key, private_key):
    print("-->sign_message")

    signed_message = private_key.sign(
        
        encrypted_message,
        
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signed_message


def encrypt_message(conn, message, sender_email, recipient_email, sender_private_key):
    print("-->encrypt_message")
    symmetric_key = generate_symmetric_key()
    encrypted_message = encrypt_message_with_AES(message, symmetric_key)
    recipient_public_key = lookup_public_key_by_email(conn, recipient_email)
    encrypted_key = encrypt_message_key_with_RSA(symmetric_key, recipient_public_key)
    signed_message = sign_message(encrypted_message, encrypted_key, sender_private_key)
    return (sender_email, recipient_email, encrypted_message, encrypted_key, signed_message)