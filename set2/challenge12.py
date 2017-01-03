#!/usr/bin/env python3

# Cryptopals Challenge, Set 2, Challenge 12
# CJ Guttormsson
# 2017-01-03

import sys
sys.path.append('..')
from common import (get_random_key, base64_to_bytes, aes_128_ecb_encrypt,
                    guess_mode)
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
    """Given the algorithm above, find the unknown data, and then the key."""
    # This only works for ECB
    assert guess_mode(alg) == 'ECB'

    block_length = guess_block_length(alg)

    # Create a one-byte-short block, and fill in all possible last bytes.
    # For each such byte, record what the first encrypted block looks like.
    # Match this information against 
    known_bytes = b''
    for offset in range(0, 17):
        # block of arbitrary data, ending with the known beginning bytes of
        # the unknown data. If there is enough known data, then there will be
        # no arbitrary data.
        known_bytes_suffix = known_bytes[-16:]
        block = bytes(max(block_length - offset - 1, 0)) + known_bytes_suffix
        results = {}
        # Try adding all possible bytes to the end
        for possible_byte in (bytes([b]) for b in range(0, 256)):
            results[alg(block + possible_byte)[:16]] = possible_byte
        # Use the table we made to figure out which byte was correct, and add it
        # to the list of known bytes
        if offset < 16:
            new_byte = results[alg(bytes(block_length - offset - 1))[:16]]
        else:
            new_byte = results[alg(bytes(block_length - offset - 1 + 16))[16:32]]
        known_bytes += new_byte
        

    return known_bytes

    



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
    print(guess_unknown_string(encrypt_ecb_with_unknowns))
    print(UNKNOWN_DATA[:16])

    print('Challenge 12 completed successfully.')


if __name__ == '__main__':
    main()
