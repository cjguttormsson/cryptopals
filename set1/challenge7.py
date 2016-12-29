#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 7
# CJ Guttormsson
# 2016-12-29

from common import base64_to_bytes
from Crypto.Cipher import AES

#############
# CONSTANTS #
#############


#################
# NEW FUNCTIONS #
#################

def aes_128_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """Take a stream of encrypted bytes and decrypt them with the key."""
    # I believe that this only works with a key of length 16
    # TODO: Figure out if this is true
    assert len(key) == 16

    # Set up the cipher and perform the decryption. No salt or IV.
    cipher = AES.new(key, AES.MODE_ECB) 
    return cipher.decrypt(data)

########
# MAIN #
########


def main():
    with open('7.txt') as data_file:
        bindata = base64_to_bytes(data_file.read())
    key = b'YELLOW SUBMARINE'

    decrypted = aes_128_ecb_decrypt(bindata, key)

    # If this decoding fails, then the data was not unencrypted correctly
    message = decrypted.decode('utf-8')

    print('Challenge 7 completed successfully.')


if __name__ == '__main__':
    main()
