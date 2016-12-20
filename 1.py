#!/usr/bin/env python3

# Cryptopals challenge, set 1

import base64
import itertools
import string
from collections import Counter
from math import sqrt
from itertools import cycle


#############
# CONSTANTS #
#############

CHAR_FREQ = {' ': 18.28846265, 'e': 10.26665037, 't': 7.51699827,
             'a': 6.53216702, 'o': 6.15957725, 'n': 5.71201113,
             'i': 5.66844326, 's': 5.31700534, 'r': 4.98790855,
             'h': 4.97856396, 'l': 3.31754796, 'd': 3.28292310,
             'u': 2.27579536, 'c': 2.23367596, 'm': 2.02656783,
             'f': 1.98306716, 'w': 1.70389377, 'g': 1.62490441,
             'p': 1.50432428, 'y': 1.42766662, 'b': 1.25888074,
             'v': 0.79611644, 'k': 0.56096272, 'x': 0.14092016,
             'j': 0.09752181, 'q': 0.08367550, 'z': 0.05128469}


#############
# FUNCTIONS #
#############

def hex_to_bytes(s):
    """take an encoded string (type str) of hex characters and return bytes"""
    return bytearray.fromhex(s)


def bytes_to_hex(s):
    """take bytes and return an encoded string of hex characters"""
    return ''.join('{:02x}'.format(b) for b in s)


def hex_to_base64(s):
    """take hex string and return their base64 form for pretty-printing"""
    return base64.b64encode(hex_to_bytes(s))


def bytes_to_base64(s):
    """take bytes and return their base64 form for pretty-printing"""
    return base64.b64encode(s)


def xor_bytestrings(s1, s2):
    """bitwise xor two equal-length strings of bytes"""
    return bytearray(b1 ^ b2 for b1, b2 in zip(s1, s2))


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


def english_probability(s):
    """determine the probability that a given ascii string is in english"""
    # Use cosine similarity to determine how much the string resembles
    # the letter distribution of English.

    # Begin by making `s` into a vector of fractions, like CHAR_FREQ
    cntr = Counter(c.lower() for c in s if c.isalpha() or c == ' ')
    total_chars = sum(n for _, n in cntr.items())
    vec = {c: freq/total_chars for c, freq in cntr.items()}

    # Do the actual calculation. `vec` is 'a' and `CHAR_FREQ` is 'b'
    a_dot_b = sum(pair[0] * pair[1] for pair in zip_dict(vec, CHAR_FREQ))
    mag_a = sqrt(sum(freq**2 for freq in vec.values()))
    mag_b = sqrt(sum(freq**2 for freq in CHAR_FREQ.values()))

    return a_dot_b / (mag_a * mag_b)


def zip_dict(*dicts):
    """zip two dicts by their keys"""
    for key in set(dicts[0]).intersection(*dicts[1:]):
        yield tuple(d[key] for d in dicts)


def repeated_key_encrypt(plaintext, key):
    """take a plain string and encypt it with another string"""
    # Convert both pieces to bytes if necessary
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')

    # xor together the things
    return bytes(p_c ^ k_c for p_c, k_c in zip(plaintext, cycle(key)))


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
