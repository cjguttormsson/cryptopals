#!/usr/bin/env python3

# Cryptopals Challenge, Set 2, Challenge 11
# CJ Guttormsson
# 2017-01-03

import sys
sys.path.append('..')
from common import aes_128_ecb_encrypt, aes_128_cbc_encrypt, is_ecb
import random


#################
# NEW FUNCTIONS #
#################


def get_random_key(key_len: int = 16) -> bytes:
    """Return a random string of bytes of length key_len, for cyptography."""
    return bytes(random.randint(0, 255) for _ in range(key_len))


def random_pad(data: bytes) -> bytes:
    """Pad the data with 5-10 bytes of random data in the front and back."""
    before = bytes(random.randint(0, 255) for _ in range(5, 10))
    after = bytes(random.randint(0, 255) for _ in range(5, 10))
    return before + data + after


def random_encrypt(data: bytes) -> bytes:
    """Randomly encrypt the data (padded randomly) with a random key."""
    encryption_alg = random.choice([aes_128_cbc_encrypt, aes_128_ecb_encrypt])
    return encryption_alg(random_pad(data), get_random_key())


def guess_mode(alg) -> str:
    """Guess if the given encryption algorithm is running in ECB or CBC mode"""
    plaintext = b'e'*48
    if is_ecb(alg(plaintext)):
        return 'ECB'
    else:
        return 'CBC'


########
# MAIN #
########


def main():
    # get_random_key is random
    assert get_random_key() != get_random_key()

    # random_pad pads between 10 and 20 chars
    assert 10 <= len(random_pad(b'')) <= 20

    print(random_encrypt(b'Hi I\'m katy *holds up spork*'))
    print(guess_mode(random_encrypt))
    d = {'ECB': 0, 'CBC': 0}
    for i in range(10000):
        d[guess_mode(random_encrypt)] += 1
    print(d)
    print('Challenge 11 completed successfully.')


if __name__ == '__main__':
    main()
