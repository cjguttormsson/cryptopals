#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 6
# CJ Guttormsson
# 2016-12-28

from base64 import b64decode
from common import single_char_decode, repeated_key_encrypt

#############
# CONSTANTS #
#############


# Number of bits in every possible byte
N_BITS = {n: bin(n).count('1') for n in range(256)}


#################
# NEW FUNCTIONS #
#################


def hamming_distance(bs1: bytes, bs2: bytes) -> int:
    """Get the number of differing bits between two bytestrings."""
    return sum(N_BITS[b1 ^ b2] for b1, b2 in zip(bs1, bs2))


def base64_to_bytes(s: str) -> bytes:
    """Turn a base64-encoded string into a decoded `bytes` object."""
    return b64decode(s)


def load_base64_file(f_name: str) -> bytes:
    """Load a file encoded with base64 and return its decoded contents."""
    with open(f_name) as file:
        return base64_to_bytes(file.read())


def guess_keysize(ciphertext: bytes) -> int:
    """Guess the length of the repeated key used to encrypt a ciphertext."""
    results = []
    for keysize in range(2, 41):
        # Break the ciphertext into `keysize`-length chunks
        keysize_repeats = len(ciphertext) // keysize
        blocks = [ciphertext[i*keysize:i*keysize+keysize]
                  for i in range(keysize_repeats)]

        # Calculate the hamming distance in between consecutive blocks
        distances = [hamming_distance(block1, block2)
                     for block1, block2 in zip(blocks, blocks[1:])]

        # Get the average hamming distance, normalized by keysize
        average = sum(d / keysize for d in distances) / keysize_repeats
        results.append((average, keysize))

    # The best result has the lowest avereage hamming distance
    return min(results)[1]
    # return sorted(results)[:5]


def repeating_key_decode(ciphertext: bytes) -> str:
    """Take a ciphertext encoded with an unknown key and dechiper it."""

    # Get the probable keysize, upon which the rest of the calculations rely
    keysize = guess_keysize(ciphertext)
    guessed_key = [None] * keysize

    # Try to guess one letter of the key at a time
    for char_pos in range(keysize):
        # Build a string by taking every keysize'th letter starting at start
        to_decode = ciphertext[char_pos::keysize]

        # Use single_char_decode to guess what letter was used in this
        # position of the key.
        guessed_key[char_pos] = single_char_decode(to_decode)['k']

    # Add all the letters back together to get the answer
    return bytes(guessed_key)

########
# MAIN #
########


def main():
    assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37

    content = load_base64_file('6.txt')
    key = repeating_key_decode(content)
    print(key)
    print(repeated_key_encrypt(content, key).decode('ascii'))

    # I don't even know what to assert for this
    print('Challenge 6 completed successfully.')


if __name__ == '__main__':
    main()
