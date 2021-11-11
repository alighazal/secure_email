from send import encrypt_message
from receive import decrypt_message
#mstfrom typing_extensions import runtime
import db
from db import *
from server import *
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def register_user(conn):
    print("Enter email: ")
    email = input()
            
    #print("Enter public key:")
    #public_key = input()

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

def generate_public_private_key_pair():
    ## key_sizes = [2048 * (1/2) , 2048, 2048 * 2] 
    # TODO MAKE DYNAMIC 

    has_password = True
    password = b"mypassword" # convert input to bytes

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048*2
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
        print("file exits")

    with open( "./key/private_key.pem", 'wb') as pem_private_out:
        pem_private_out.write(private_pem)

    with open(  "./key/public_key.pem", 'wb') as pem_public_out:
        pem_public_out.write(public_key)

    print (f"Public Key: {public_key}")
    print (f"Private Key: {private_pem}")

def read_user_private_key():
    #prompt from user to paste, or read from file path <-------------------------------------------------------------

def encrypt(message, sender_email, recipient_email):
    sender_private_key = read_user_private_key()
    encrypt_message(message, sender_email, recipient_email, sender_private_key)

def decrypt(file):
    #extract sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key from file <----------------------------------------------------
    recipient_private_key = read_user_private_key()
    (verification_result, message) = decrypt_message(sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key, recipient_private_key)

def console_menu():
    choice = ""
    while choice != "6":
        print("Choose one of the following options:")
        print("1- Generate key pair")
        print("2- Sign up as a new user")
        print("3- Verify user email-key association")
        print("4- Send message")
        print("5- Decrypt message")
        print("6- Exit")
        choice = input()

        if choice == "1": #generate key pair
            generate_public_private_key_pair()

        elif choice == "2": #sign up
            # TODO (OPTIONAL) SINGING-IN
            register_user(conn)
        
        elif choice == "3": #verify association
            print("Enter email: ")
            email = input()
            
            print("Enter private key key:")
            private_key = input()
            
            print("Getting challenge....")
            token_challenge = get_challenge_token(conn, email)
            print(f"Challeng token: {token_challenge}")
            challenge_response = rsa.decrypt(token_challenge, private_key)
            print(f"Challenge respone: {challenge_response}")
            verifcation_result = verify_user(conn, email, challenge_response)
            if verifcation_result == 1:
                print(f"Server verified user association for: {email}")
            else:
                print(f"User association not verified for: {email}")
        
        elif choice == "4": #send
            #read message file path from user <-----------------------------------------------------------------------------------
            print("Message file path: ")
            message_file_path = input()
            #extract the message content

            print("Enter your email (sender email): ")
            sender_email = input()

            print("Enter the reciepient email: ")
            recipient_email = input()

            encrypt(message, sender_email, recipient_email)

        elif choice == "5": #recieve  
            #read file path from user, the file should contain all the required info <-----------------------------------------------------------
            decrypt(recieved_file)
        else:
            print("Please choose a valid option")

if __name__ == '__main__':
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
        #run_script(conn, "DROP TABLE users;")
        run_script(conn, sql_create_users_table)
        console_menu()

    else:
        print("Error! cannot create the database connection.")