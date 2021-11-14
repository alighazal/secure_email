import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from send import *
from db import *
from receive import *

def create_user(conn, user):
    sql = ''' INSERT INTO users(email,public_key,challenge_token_digest,verification_status)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, user)
    conn.commit()
    return cur.lastrowid


def sign_up(conn, email, public_key):
    #challenge_token = prepare_challenge(email)
    user = (email, public_key, str("SSSSSSSSSSSSSSSSSSSSSSSSS"), 0)
    user_id = create_user(conn, user)
    return user_id


def generate_public_private_key_pair():

    print ("""
Choose Key Length:
    - 1024
    - 2048
    - 4096 (Most Secure)
        """)
    keysize = input() ## Add Verification

    has_password = True

    print("Enter Password: ")
    password = input()
    password = str.encode(password)
    #password = b"mypassword" # convert input to bytes

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(keysize)
    )

    if (has_password):
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
    else:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm= serialization.NoEncryption() 
            )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,    
    )


    directory = "key"
    parent_dir = os.getcwd()
    key_path = os.path.join(parent_dir, directory)

    try:
        os.mkdir(key_path)
    except:
        print("key folder already exits (will be overwritten)")

    with open( "./key/private_key.pem", 'wb') as pem_private_out:
        pem_private_out.write(private_pem)

    with open(  "./key/public_key.pem", 'wb') as pem_public_out:
        pem_public_out.write(public_key)

    print (f"Public Key: {public_key}")
    print (f"Private Key: {private_pem}")

def register_user(conn):
    print("Enter email: ")
    email = input()

    parent_dir = os.getcwd()
    key_path = os.path.join(parent_dir, "key")

    with open("./key/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1,
    )

    print(type(public_key_pem))
    print(public_key_pem)
        
    print("Registering user....")
    user_id = sign_up(conn, email, public_key_pem)
            
    print(f"Created user with id {user_id}")

def read_user_private_key():

    parent_dir = os.getcwd()
    key_path = os.path.join(parent_dir, "key")

    print("Enter Password: ")
    password = input()

    with open("./key/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=str.encode(password),
        )
    return private_key

def encrypt(conn, message, sender_email, recipient_email):
    sender_private_key = read_user_private_key()
    (sender_email, recipient_email, encrypted_message, encrypted_key, signed_message) = encrypt_message(conn, message, sender_email, recipient_email, sender_private_key)
    print (sender_email, recipient_email)

    with open( "./message.encrypted.txt", 'wb') as encrypted_msg:
        encrypted_msg.write(encrypted_message)
    with open( "./encrypted_key.txt", 'wb') as encrypted_msg:
        encrypted_msg.write(encrypted_key)
    with open( "./signed_message.txt", 'wb') as encrypted_msg:
        encrypted_msg.write(signed_message)

def decrypt(conn):
    #extract sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key from file <----------------------------------------------------
   
    ## this is reading the private key of the recipiant "ali"
    print("Enter Path of Private Key: ")
    filepath = input()

    print("Enter Password: ")
    password = input()

    with open(filepath, "rb") as key_file:
        recipient_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=str.encode(password),
        )

    print("What Was Your Email: ")
    recipient_email = input()
    
    print("Who Do You think Have Sent this Email?: ")
    sender_email = input()

    #Example:
    #sender_email = "may@mail.com"
    #recipient_email = "ali@mail.com"

    with open("./message.encrypted.txt", "rb") as msg_encrypted:
        encrypted_message = msg_encrypted.read()
    
    with open("./signed_message.txt", "rb") as msg_signed:
        message_signature = msg_signed.read()
    
    with open("./encrypted_key.txt", "rb") as msg_encryption_key:
        encrypted_message_key = msg_encryption_key.read()
    
    decrypted_message = decrypt_message(conn, sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key, recipient_private_key)
    
    return decrypted_message


def console_menu():
    choice = ""
    while choice != "6":
        print("Choose one of the following options:")
        print("1- Generate key pair")
        print("2- Sign up as a new user")
        print("3- Verify user email-key association") #TODO VERIFIY USER
        print("4- Send message")
        print("5- Decrypt message")
        print("6- Exit")
        choice = input()

        if choice == "1": #generate key pair
            generate_public_private_key_pair()

        elif choice == "2": #sign up
            register_user(conn)
        
        elif choice == "4": #send
            # read message file path from user 
            # -----------------------------------------------------------------------------------
            print("Message file path: ")
            
            filepath = input()
            message = open(filepath, 'rb').read()

            print("Enter your email (sender email): ")
            sender_email = input()

            print("Enter the reciepient email: ")
            recipient_email = input()

            encrypt(conn, message, sender_email, recipient_email)

        elif choice == "5": #recieve  
            #read file path from user, the file should contain all the required info <-----------------------------------------------------------
            decrypted_message = decrypt(conn)

            with open( "./message.decrypred.txt", 'wb') as decrypted_msg:
                decrypted_msg.write(decrypted_message)


if __name__ == '__main__':

    print ("""
  ____                                  _____                    _  _ 
 / ___|   ___   ___  _   _  _ __  ___  | ____| _ __ ___    __ _ (_)| |
 \___ \  / _ \ / __|| | | || '__|/ _ \ |  _|  | '_ ` _ \  / _` || || |
  ___) ||  __/| (__ | |_| || |  |  __/ | |___ | | | | | || (_| || || |
 |____/  \___| \___| \__,_||_|   \___| |_____||_| |_| |_| \__,_||_||_|
                                                                      
    """)

    conn = create_connection(r".\sec_email.db")

    sql_create_users_table = """ 
                                CREATE TABLE IF NOT EXISTS users (
                                email text PRIMARY KEY,
                                public_key text,
                                challenge_token_digest text,
                                verification_status integer
                                ); """
    if conn is not None:
    # create projects table
        run_script(conn, sql_create_users_table)
        console_menu()