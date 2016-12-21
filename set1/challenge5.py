#!/usr/bin/env python3

# Cryptopals challenge, set 1

import base64
import itertools
import string
from collections import Counter
from math import sqrt
from itertools import cycle




def single_char_decode(ciphertext):
    """find the secret byte a string was encoded with and decode it"""
    # First get bytes form so we can actually do stuff with it
    ba = hex_to_bytes(ciphertext)

    # Iterate over every possible char and try to decipher using it
    results = []
    for c in string.printable:
        try:
            c = ord(c)
            result = xor_bytestrings(ba, itertools.repeat(c))
            for byte in result:
                if chr(byte) not in string.printable:
                    break
            else:
                result = result.decode('ascii')
                results.append((english_probability(result), result))
        except UnicodeDecodeError:
            pass

    return sorted(results, reverse=True)[0]

########
# MAIN #
########


if __name__ == '__main__':
    # Challenge 1
    var = ('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706'
           'f69736f6e6f7573206d757368726f6f6d')
    print('1 -', hex_to_base64(var))

    # Challenge 2
    s1 = hex_to_bytes("1c0111001f010100061a024b53535009181c")
    s2 = hex_to_bytes("686974207468652062756c6c277320657965")
    result = xor_bytestrings(s1, s2)
    print('2 -', result, bytes_to_hex(result))

    # Challenge 3
    ciphertext = ('1b37373331363f78151b7f2b783431333d78397828372d363c783'
                  '73e783a393b3736')
    print('3 -', single_char_decode(ciphertext)[:3])

    # Challenge 4
    plain = ("Burning 'em, if you ain't quick and nimble"
             "\nI go crazy when I hear a cymbal")
    print('4 -', bytes_to_hex(repeated_key_encrypt(plain, 'ICE')))
