from server import look_up
def lookup_public_key_by_email(recipient_email):
    public_key = look_up(recipient_email);
    return public_key

def verify_message(sender_public_key, encrypted_message, encrypted_message_key, message_signature):

def decrypt_message_key_with_RSA(emcrypted_message_key, recipient_private_key):

def decrypt_message_with_AES(encrypted_message, decrypted_symmetric_key):

def decrypt_message(sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key, recipient_private_key):
    sender_public_key = lookup_public_key_by_email(sender_email)
    verification_result = verify_message(sender_public_key, encrypted_message, message_signature)
    if verification_result:
        decrypted_symmetric_key = decrypt_message_key_with_RSA(encrypted_message_key, recipient_private_key)
        decrypted_message = decrypt_message_with_AES(encrypted_message, decrypted_symmetric_key)
        return (verification_result, decrypted_message)
    else: return (verification_result, '')
