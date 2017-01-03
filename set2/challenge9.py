#!/usr/bin/env python3

# Cryptopals Challenge, Set 2, Challenge 9
# CJ Guttormsson
# 2016-12-31

import sys
sys.path.append('..')
from common import hex_to_bytes

#################
# NEW FUNCTIONS #
#################


def pkcs7_pad(text: bytes, pad_len: int = 16) -> bytes:
    """Pad out some text to a multiple of pad_len bytes"""
    extra_len = pad_len - (len(text) % pad_len)
    return text + bytes([extra_len] * extra_len)

########
# MAIN #
########


def main():
    result = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pkcs7_pad(b'YELLOW SUBMARINE', 20) == result
    print('Challenge 9 completed successfully.')


if __name__ == '__main__':
    main()
