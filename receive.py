from server import look_up
def lookup_public_key_by_email(recipient_email):
    public_key = look_up(recipient_email);
    return public_key

def decrypt_signature(sender_public_key, message_signature):
    #<------------------------------------------------------------------------------------------------
    return (encrypted_message, encrypted_key)

def decrypt_message_key_with_RSA(encrypted_key, recipient_private_key):
    #<------------------------------------------------------------------------------------------------
    return decrypted_symmetric_key

def decrypt_message_with_AES(encrypted_message, decrypted_symmetric_key):

def verfiy_message_integrity(decrypted_message, message_hash):
    #hash the message
    #compare hashes
    #return true if match
    #else, return false

def decrypt_message(sender_email, recipient_email, message_signature):
    sender_public_key = lookup_public_key_by_email(sender_email)
    (encrypted_message, encrypted_key) = decrypt_signature(sender_public_key, message_signature)
    #get the private key from ClientUI<-------------------------------------------------------------------------------------
    decrypted_symmetric_key = decrypt_message_key_with_RSA(encrypted_key, recipient_private_key)
    (decrypted_message, message_hash) = decrypt_message_with_AES(encrypted_message, decrypted_symmetric_key)
    if(verfiy_message_integrity(decrypted_message, message_hash)):
        return (decrypted_message)
    else
        print("message corrupted")    
   
