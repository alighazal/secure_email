import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key_sizes = [2048 * (1/2) , 2048, 2048 * 2]

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
