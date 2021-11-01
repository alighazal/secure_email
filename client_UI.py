from send import encrypt_message
from receive import decrypt_message

def register_user():

def generate_public_private_key_pair():

def read_user_private_key():
    #prompt from user to paste, or read from file path

def encrypt():
    sender_private_key = read_user_private_key()
    encrypt_message(message, sender_email, recipient_email, sender_private_key)

def decrypt(file):
    #extract sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key from file
    recipient_private_key = read_user_private_key()
    (verification_result, message) = decrypt_message(sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key, recipient_private_key)