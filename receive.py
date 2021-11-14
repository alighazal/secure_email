from server import select_user_by_email
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidSignature


def lookup_public_key_by_email(conn, recipient_email):
    public_key_pem = select_user_by_email(conn, recipient_email)
    public_key = serialization.load_pem_public_key(
        public_key_pem
    )
    return public_key

def decrypt_signature(sender_public_key, message_signature, message ):

    try:
        sender_public_key.verify(

            message_signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False

    return True
    ## TODO EXCEPTION HANDLING --> IF NOT VERFIED RERTURN FALSE
    # ELSE ALWAYS RETURN TRUE 

def decrypt_message_key_with_RSA(encrypted_key, recipient_private_key):
    #<------------------------------------------------------------------------------------------------

    key_decrypted = recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return key_decrypted

def decrypt_message_with_AES(encrypted_message, decrypted_symmetric_key):

    f = Fernet(decrypted_symmetric_key)
    decrypted_message = f.decrypt(encrypted_message)
    print ("Decrypted Message: ", decrypted_message)

    return decrypted_message

def verfiy_message_integrity(decrypted_message, message_hash):
    #hash the message
    #compare hashes
    #return true if match
    #else, return false
    return 0
    
def decrypt_message(conn, sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key, recipient_private_key):
    sender_public_key = lookup_public_key_by_email(conn, sender_email)

    isVerified =  decrypt_signature(sender_public_key, message_signature, encrypted_message)
    #get the private key from ClientUI<-------------------------------------------------------------------------------------
    
    if( not isVerified):
        print("!! Message has an Invalid Signature !!")
        return b""    

    decrypted_symmetric_key = decrypt_message_key_with_RSA(encrypted_message_key, recipient_private_key)
    decrypted_message = decrypt_message_with_AES(encrypted_message, decrypted_symmetric_key)

    return (decrypted_message)
   
