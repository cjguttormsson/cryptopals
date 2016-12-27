#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 2
# CJ Guttormsson
# 2016-12-19

from common import hex_to_bytes

#################
# NEW FUNCTIONS #
#################


def bytes_to_hex(bs: bytes) -> str:
    """Turn a `bytes` object into its hex representation."""
    return ''.join('{:02x}'.format(b) for b in bs)


def xor_bytes(bs1: bytes, bs2: bytes) -> bytes:
    """Bitwise xor two equal-lenth `bytes` objects."""
    return bytes(b1 ^ b2 for b1, b2 in zip(bs1, bs2))


########
# MAIN #
########


def main():
    input_a_hex = '1c0111001f010100061a024b53535009181c'
    input_b_hex = '686974207468652062756c6c277320657965'
    output_hex = '746865206b696420646f6e277420706c6179'

    input_a_bytes = hex_to_bytes(input_a_hex)
    input_b_bytes = hex_to_bytes(input_b_hex)

    input_xored = xor_bytes(input_a_bytes, input_b_bytes)

    assert bytes_to_hex(input_xored) == output_hex
    print('Challenge 2 passed successfully.')


if __name__ == '__main__':
    main()
