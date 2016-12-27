#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 1
# CJ Guttormsson
# 2016-12-19

from base64 import b64encode

#################
# NEW FUNCTIONS #
#################


def hex_to_bytes(s: str) -> bytes:
    """Turn a string of hex characters into a `bytes` object."""
    return bytes.fromhex(s)


def hex_to_base64(s: str) -> str:
    """Turn a string of hex characters into a base64-encoded string."""
    return b64encode(hex_to_bytes(s)).decode('ascii')

########
# MAIN #
########


def main():
    hex_str = ('49276d206b696c6c696e6720796f757220627261696e206c'
               '696b65206120706f69736f6e6f7573206d757368726f6f6d')
    b64_str = ('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs'
               'aWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    assert hex_to_base64(hex_str) == b64_str
    print('Challenge 1 passed succesfully.')


if __name__ == '__main__':
    main()
