from cryptography.fernet import Fernet

import hashlib 

import server

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_message_with_AES(message, key):
    #encrypt the message digest with the message to verify integrity
    message_digest = hashlib.sha256(message.encode('utf-8')).digest()
    f = Fernet(key)
    message_length = len(message)
    encrypted_message = f.encrypt(str(message_length) + '#' + message + message_digest) # Is this valid?? how do I split for decryption
    return encrypted_message

def lookup_public_key_by_email(recipient_email):
    reciepient_public_key = server.look_up(recipient_email)
    return reciepient_public_key

def encrypt_message_key_with_RSA(message_key, key):

def sign_message(encrypted_message, private_key):

def encrypt_message(message, sender_email, recipient_email, sender_private_key):
    symmetric_key = generate_symmetric_key()
    encrypted_message = encrypt_message_with_AES(message, symmetric_key)
    recipient_public_key = lookup_public_key_by_email(recipient_email)
    encrypted_key = encrypt_message_key_with_RSA(symmetric_key, recipient_public_key)
    message_signature = sign_message(encrypted_message, encrypted_key, sender_private_key)
    return (sender_email, recipient_email, encrypted_message, encrypted_key, message_signature)