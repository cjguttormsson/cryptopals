#!/usr/bin/env python3

# Cryptopals Challenge, Set 2, Challenge 12
# CJ Guttormsson
# 2017-01-03

import sys
sys.path.append('..')
from common import (get_random_key, base64_to_bytes, aes_128_ecb_encrypt,
                    guess_mode, pkcs7_pad)
import random
import itertools
from pprint import pprint


#############
# CONSTANTS #
#############

# A random but constant key
UNKNOWN_KEY = get_random_key()

# The given data, that is not known in its decoded form
UNKNOWN_DATA = base64_to_bytes("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")


#################
# NEW FUNCTIONS #
#################

def encrypt_ecb_with_unknowns(data: bytes) -> bytes:
    """Pad given data with the unknown data and encrypt with the unknown key"""
    return aes_128_ecb_encrypt(data + UNKNOWN_DATA, UNKNOWN_KEY)


def guess_block_length(alg) -> int:
    """Given an encryption algorithm, guess the block length it uses."""
    # Guess by observing how the size of the output text, which is always a
    # multiple of the block length, changes.
    last_length = len(alg(b''))
    for data_length in itertools.count(1):
        new_length = len(alg(b'\0' * data_length))
        if new_length > last_length:
            return new_length - last_length

def guess_unknown_string(alg) -> bytes:
    """Given the algorithm above, find the unknown data."""
    assert guess_mode(alg) == 'ECB'
    block_length = guess_block_length(alg)

    # Guess one character at a time by shifting the unknown text so that only
    # one unknown character is in the block we are looking at

    known_bytes = b''
    while True:
        # figure out how much padding we need, and which block we're looking at
        empty_block = bytes(block_length - (len(known_bytes) % 16) - 1)
        start = (len(known_bytes) // 16) * 16
        
        # Create a lookup table for each possible byte (result block -> byte)
        results = {}
        for possible_byte in (bytes([b]) for b in range(256)):
            result = alg(empty_block+known_bytes+possible_byte)[start:start+16]
            results[result] = possible_byte

        # Look at what the answer should be, then use that to figure out
        # which possible byte was correct
        expected_block = alg(empty_block)[start:start+16]
        if expected_block in results:
            known_bytes += results[expected_block]
        else:
            break

    # The result seems to return an extra b'\x01' at the end for some reason
    # TODO: investigate
    return known_bytes[:-1]

    



########
# MAIN #
########


def main():
    # Determine block length
    block_length = guess_block_length(encrypt_ecb_with_unknowns)
    assert block_length == 16
   
    # Determine the algorithm being used
    assert guess_mode(encrypt_ecb_with_unknowns) == 'ECB'

    # Guess the key
    assert guess_unknown_string(encrypt_ecb_with_unknowns) == UNKNOWN_DATA

    print('Challenge 12 completed successfully.')


if __name__ == '__main__':
    main()
