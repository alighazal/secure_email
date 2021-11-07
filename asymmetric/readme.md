hello there,

in `key_generation.py` we have the code related to generating keys (dah!) it still needs to be customized to to users input

in `key_loading.py`, we have the code used for pub/private key loading

the interesting part is `msg_enc` and `msg_dec`. as their names indicate, the `msg_enc.py` includes the code used to encrypt the message in the file `message.txt`. and `msg_dec.py` is used to decrypt the content in the file `message.encryped.txt`.

again, this could needs customization ... we will finish this soon isa.

to use this code, first of all, run `python ./key_generation.py` then you can alter the content of message and see the encrypted and decrypted files genereated
