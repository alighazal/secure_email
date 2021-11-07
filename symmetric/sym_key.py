from cryptography.fernet import Fernet

message = b"my name is Ali Ghazal"
print ("Original Message:", message)

key = Fernet.generate_key()
print ("Symmetric Key: ", key)

f = Fernet(key)
token = f.encrypt(message)
print ("Encrypted Message: ", token)

dec = f.decrypt(token)
print ("Encrypted Message:", dec)
