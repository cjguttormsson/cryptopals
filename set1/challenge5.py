#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 5
# CJ Guttormsson
# 2016-12-21

from common import bytes_to_hex
from itertools import cycle

#################
# NEW FUNCTIONS #
#################


def repeated_key_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Take a plain string and encypt it with another string."""
    return bytes(p_c ^ k_c for p_c, k_c in zip(plaintext, cycle(key)))


########
# MAIN #
########


def main():
    plaintext = (b'Burning \'em, if you ain\'t quick and nimble\n'
                 b'I go crazy when I hear a cymbal')
    key = b'ICE'
    ciphertext = repeated_key_encrypt(plaintext, key)

    result_hex = ('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d'
                  '63343c2a26226324272765272a282b2f20430a652e2c652a31'
                  '24333a653e2b2027630c692b20283165286326302e27282f')

    assert bytes_to_hex(ciphertext) == result_hex
    print('Challenge 5 completed successfully.')


if __name__ == '__main__':
    main()
