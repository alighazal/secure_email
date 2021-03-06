import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from send import *
from db import *
from receive import *

from server import create_user, sign_up, verify_user

def generate_public_private_key_pair():

    keysizes = [1024, 2048, 4096 ]
    keysize = -1
    has_password = True 
    while (int(keysize) not in [0,1,2]):
        print ("""
    Choose Key Length (0,1,2):
        0- 1024
        1- 2048
        2- 4096 (Most Secure)
            """)
        keysize = input() ## Add Verification



    print("Enter Password: ")
    password = input()
    password = str.encode(password)
    #password = b"mypassword" # convert input to bytes

    print("Enter email: ")
    email = input()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(keysizes[int(keysize)])
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


    directory = email
    parent_dir = os.getcwd()
    key_path = os.path.join(parent_dir, directory)

    try:
        os.mkdir(key_path)
    except:
        print("key folder already exits (will be overwritten)")

    with open( f"./{email}/private_key.pem", 'wb') as pem_private_out:
        pem_private_out.write(private_pem)

    with open(  f"./{email}/public_key.pem", 'wb') as pem_public_out:
        pem_public_out.write(public_key)

    print (f"Public Key: {public_key}")
    print (f"Private Key: {private_pem}")

def register_user(conn):
    print("Enter email: ")
    email = input()

    parent_dir = os.getcwd()
    key_path = os.path.join(parent_dir, "key")

    with open(f"./{email}/public_key.pem", "rb") as key_file:
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

def read_user_private_key(email):

    print("Enter Password: ")
    password = input()

    with open( f"./{email}/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=str.encode(password),
        )
    return private_key

def encrypt(conn, message_name , message, sender_email, recipient_email):
    directory = message_name + "_" + sender_email + "_" + recipient_email
    parent_dir = os.getcwd()
    message_path = os.path.join(parent_dir, directory)

    try:
        os.mkdir(message_path)
    except:
        print("key folder already exits (will be overwritten)")

    sender_private_key = read_user_private_key(sender_email)
    (sender_email, recipient_email, encrypted_message, encrypted_key, signed_message) = encrypt_message(conn,directory,  message_name,  message, sender_email, recipient_email, sender_private_key)
    print (sender_email, recipient_email)

    encryption_info = {
        "sender_email": sender_email ,
        "recipient_email": recipient_email ,
        "file_name": message_name ,
    }

    with open(f"./{directory}/encryption_info.json", 'w') as outfile:
        json.dump(encryption_info, outfile)

    with open( f"./{directory}/{message_name}.encrypted", 'wb') as encrypted_msg:
        encrypted_msg.write(encrypted_message)
    with open( f"./{directory}/encrypted_key.txt", 'wb') as encrypted_msg:
        encrypted_msg.write(encrypted_key)
    with open( f"./{directory}/{message_name}.signed", 'wb') as encrypted_msg:
        encrypted_msg.write(signed_message)
    

def decrypt(conn,encrypted_message_path,  encrypted_message_filename, sender_email, recipient_email):
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
   
    #Example:
    #sender_email = "may@mail.com"
    #recipient_email = "ali@mail.com"

    with open(f"./{encrypted_message_path}/{encrypted_message_filename}.encrypted", "rb") as msg_encrypted:
        encrypted_message = msg_encrypted.read()
    
    with open(f"./{encrypted_message_path}/{encrypted_message_filename}.signed", "rb") as msg_signed:
        message_signature = msg_signed.read()
    
    with open(f"./{encrypted_message_path}/encrypted_key.txt", "rb") as msg_encryption_key:
        encrypted_message_key = msg_encryption_key.read()
    
    with open(f"./{encrypted_message_path}/{encrypted_message_filename}.hash", "rb") as msg_hahsed:
        messge_hash = msg_hahsed.read()
    
    decrypted_message = decrypt_message(conn, sender_email, recipient_email, encrypted_message, message_signature, encrypted_message_key, recipient_private_key,messge_hash, encrypted_message_filename)
    
    return decrypted_message

def verify (email):
    print ("please enter the path of the challenge file !! ")
    challenge_filepath = input()
    with open(f"./{challenge_filepath}", "rb") as challenge_file:
        encrypted_challenge = challenge_file.read()
    
    print("Enter Path of Private Key: ")
    filepath = input()

    print("Enter Password: ")
    password = input()

    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=str.encode(password),
        )
    
    challenge_response = private_key.decrypt(
        encrypted_challenge,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    verify_user(conn, email, challenge_response)

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

        elif choice == "3": #verify association
            print("Enter email: ")
            email = input()
            verify(email)
        
        elif choice == "4": #send
            # read message file path from user 
            # -----------------------------------------------------------------------------------
            print("Message file path: ")
            
            filepath = input()
            message = open(filepath, 'rb').read()

            message_name = filepath.split('/')[-1]
            

            print("Enter your email (sender email): ")
            sender_email = input()

            print("Enter the reciepient email: ")
            recipient_email = input()

            encrypt(conn, message_name, message, sender_email, recipient_email)

        elif choice == "5": #recieve  
            #read file path from user, the file should contain all the required info <-----------------------------------------------------------
           
            print("Enter Path of the folder containing your encrypted message: ")
            encrypted_message_path = input()

            try:
                with open(f'./{encrypted_message_path}/encryption_info.json') as json_file:
                    encryption_info = json.load(json_file)
                    
                    encrypted_message_filename = encryption_info["file_name"]
                    sender_email = encryption_info["sender_email"]
                    recipient_email = encryption_info["recipient_email"]
            except:
                print ("can't open the 'encryption_info' file that contains the encryption information ")
                print ("please enter the the path of the needed files manually \n ")
                
                print ("enter the name of the encrypted file ")
                encrypted_message_filename = input()
                
                print ("enter the sender email: ")
                sender_email = input()
                
                print ("enter the recipient email: ")
                recipient_email = input()

            decrypted_message = decrypt(conn, encrypted_message_path, encrypted_message_filename, sender_email, recipient_email )
            
            with open( f"./{encrypted_message_filename}.decrypred", 'wb') as decrypted_msg:
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