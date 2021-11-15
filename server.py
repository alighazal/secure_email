from db import *
#import rsa
import random
import string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def create_user(conn, user):
    sql = ''' INSERT INTO users(email,public_key,challenge_token_digest,verification_status)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, user)
    conn.commit()
    return cur.lastrowid

def select_user_by_email(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?;", (email,))
    rows = cur.fetchall()[0] 
    return rows[1]


import hashlib
    
def sign_up(conn, email, public_key):
    challenge_token = prepare_challenge(email)
    user = (email, public_key, str(challenge_token), 0)
    user_id = create_user(conn, user)

    public_key = serialization.load_pem_public_key(
            public_key)
    
    challenge_token_encrypted =  public_key.encrypt(
        str.encode(challenge_token),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(  "./challenge.txt", 'wb') as challenge_file:
        challenge_file.write(challenge_token_encrypted)


    return user_id

def look_up(conn, email): #TODO 
    select_user_by_email(conn, email)    

def prepare_challenge(email):
    # generate token
    res = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 7))
    return res
    
def get_challenge_token(conn, email):
    selected_user = select_user_by_email(conn, email)
    for row in selected_user:
        public_key = row[1]
        token =  row[2].encode('utf8')
        encrypted_token = rsa.encrypt(token, public_key)
        return encrypted_token

def verify_user(conn, email, challenge_response):
    selected_user = select_user_by_email(conn, email)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    rows = cur.fetchall()[0]
    token =  rows[2].encode('utf8')
    if token == challenge_response:
        run_script(conn, f"UPDATE users SET verification_status = 1 WHERE email = '{email}';" ) ##   TODO 
        print ('!!!! user verified !!!')
        return 1
    else:
        return 0