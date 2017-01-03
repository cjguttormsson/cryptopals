#!/usr/bin/env python3

# Cryptopals Challenge, Set 2, Challenge 10
# CJ Guttormsson
# 2017-01-03

import sys
sys.path.append('..')
from common import pkcs7_pad, aes_128_ecb_decrypt, base64_to_bytes, xor_bytes
from Crypto.Cipher import AES


#################
# NEW FUNCTIONS #
#################


def aes_128_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """Take a stream of un-encrypted bytes and encrypt them with the key."""
    # The key must be 128 bits (16 bytes) long
    assert len(key) == 16

    # Set up the cipher and perform the encryption. No salt or IV.
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def aes_128_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt a stream of cbc-encrypted bytes with the key."""
    assert len(key) == 16

    # xor each decrypted block with the previous encrypted block
    return xor_bytes(aes_128_ecb_decrypt(data, key), (b'\0' * 16) + data[:-16])


def aes_128_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt a stream of bytes with the key using block chaining."""
    # Make sure the data and key are the correct lengths
    assert len(key) == 16
    data = pkcs7_pad(data)

    # Create an output buffer for blocks and add to it one at a time
    # The buffer is initialized with the IV.
    buf = [b'\0' * 16]
    for block in [data[i:i+16] for i in range(0, len(data), 16)]:
        buf.append(aes_128_ecb_encrypt(xor_bytes(block, buf[-1]), key))

    # Combine encrypted block back together, ignoring the IV
    return b''.join(buf[1:])



########
# MAIN #
########


def main():
    # ECB round trip
    plaintext = b"""Now is the time for all good men to come to the aid of their
                    country. Lorem ipsum dolor sit amet."""
    plaintext = pkcs7_pad(plaintext)
    key = b'cryptozoologists'
    ciphertext = aes_128_ecb_encrypt(plaintext, key)
    new_plaintext = aes_128_ecb_decrypt(ciphertext, key)
    assert plaintext == new_plaintext

    # CBC decryption of provided text
    with open('10.txt') as file10:
        ciphertext = base64_to_bytes(file10.read())
    key = b'YELLOW SUBMARINE'
    decipheredtext = aes_128_cbc_decrypt(ciphertext, key)
    assert(decipheredtext.startswith(b"I'm back and I'm ringin' the bell"))

    # CBC round trip
    key = b'cryptozoologists'
    ciphertext = aes_128_cbc_encrypt(plaintext, key)
    new_plaintext = aes_128_cbc_decrypt(ciphertext, key)
    assert plaintext == new_plaintext
    
    print('Challenge 10 completed successfully.')


if __name__ == '__main__':
    main()
