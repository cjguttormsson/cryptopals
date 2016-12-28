#!/usr/bin/env python3

# Common cryptographic functionality used throughout these programs
# These are all functions that have been defined throught the course of writing
# the exercises. That code is centralized here so that it may be re-used by
# other exercises without repeating it

from base64 import b64encode
from itertools import cycle
from collections import Counter
from math import sqrt
import string
import itertools

#############
# CONSTANTS #
#############

# Frequencies of English letters (and the space character). Used to judge if an
# ASCII string appears to be in English.
CHAR_FREQ = {' ': 18.28846265, 'e': 10.26665037, 't': 7.51699827,
             'a': 6.53216702,  'o': 6.15957725,  'n': 5.71201113,
             'i': 5.66844326,  's': 5.31700534,  'r': 4.98790855,
             'h': 4.97856396,  'l': 3.31754796,  'd': 3.28292310,
             'u': 2.27579536,  'c': 2.23367596,  'm': 2.02656783,
             'f': 1.98306716,  'w': 1.70389377,  'g': 1.62490441,
             'p': 1.50432428,  'y': 1.42766662,  'b': 1.25888074,
             'v': 0.79611644,  'k': 0.56096272,  'x': 0.14092016,
             'j': 0.09752181,  'q': 0.08367550,  'z': 0.05128469}

# Numbers of bits in every possible byte
N_BITS = {n: bin(n).count('1') for n in range(256)}

#########################
# BASIC TYPE TRANSFORMS #
#########################


def hex_to_bytes(s: str) -> bytes:
    """Turn a string of hex characters into a `bytes` object."""
    return bytes.fromhex(s)


def hex_to_base64(s: str) -> str:
    """Turn a string of hex characters into a base64-encoded string."""
    return b64encode(hex_to_bytes(s)).decode('ascii')


def bytes_to_hex(bs: bytes) -> str:
    """Turn a `bytes` object into its hex representation."""
    return ''.join('{:02x}'.format(b) for b in bs)


def bytes_to_base64(bs: bytes) -> bytes:
    """Turn a `bytes` object into a base64-encoded `bytes` object."""
    return b64encode(bs)


########################
# PRIMITIVE OPERATIONS #
########################


def xor_bytes(bs1: bytes, bs2: bytes) -> bytes:
    """Bitwise xor two equal-lenth `bytes` objects."""
    return bytes(b1 ^ b2 for b1, b2 in zip(bs1, bs2))


def repeated_key_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """take a plain string and encypt it with another string"""
    return bytes(p_c ^ k_c for p_c, k_c in zip(plaintext, cycle(key)))


def hamming_distance(bs1: bytes, bs2: bytes) -> int:
    """Get the number of differing bits between two bytestrings."""
    return sum(N_BITS[b1 ^ b2] for b1, b2 in zip(bs1, bs2))


###################
# OTHER UTILITIES #
###################

# TODO: set type signature to a repeated dict from one type to another
def zip_dict(*dicts):
    """Zip dicts by their keys and yield tuples of the corresponding values."""
    for key in set(dicts[0]).intersection(*dicts[1:]):
        yield tuple(d[key] for d in dicts)


def english_probability(s: str) -> float:
    """determine the probability that a given ascii string is in english"""
    # Use cosine similarity to determine how much the string resembles
    # the letter distribution of English.

    # Begin by making `s` into a vector of fractions, like CHAR_FREQ
    cntr = Counter(c.lower() for c in s if c.isalpha() or c == ' ')
    total_chars = sum(cntr.values())
    vec = {c: freq/total_chars for c, freq in cntr.items()}

    # Do the actual calculation. `vec` is 'a' and `CHAR_FREQ` is 'b'
    a_dot_b = sum(pair[0] * pair[1] for pair in zip_dict(vec, CHAR_FREQ))
    mag_a = sqrt(sum(freq**2 for freq in vec.values()))
    mag_b = sqrt(sum(freq**2 for freq in CHAR_FREQ.values()))

    return a_dot_b / (mag_a * mag_b)


def single_char_decode(bs: bytes):
    """Find the secret byte a string was encoded with and decode it."""

    # Iterate over every possible char and try to decipher using it
    results = []

    for c in string.printable:
        try:
            # Xor the ciphertext with that character repeated, as a byte
            result = xor_bytes(bs, itertools.repeat(ord(c)))

            # Try to decode as ascii, to weed out non-text
            result_ascii = result.decode('ascii')

            # Add the result to list of possible results. The English
            # probability comes first so that it can be sorted on.
            results.append(
                (english_probability(result_ascii), result_ascii, ord(c)))

        except UnicodeDecodeError:
            # String couldn't even be decoded, so it definitely isn't English
            pass

    # Return only the best result, if one exists
    if len(results) > 0:
        probability, decoded_text, key = max(results)
        return {'d': decoded_text, 'p': probability, 'k': key}
    else:
        return {'d': '', 'p': 0, 'k': b'\0'}


def guess_keysize(ciphertext: bytes) -> int:
    """Guess the length of the repeated key used to encrypt a ciphertext."""
    results = []
    for keysize in range(2, 41):
        blocks = [ciphertext[i*keysize:i*keysize+keysize] for i in range(10)]
        result = [hamming_distance(i, j) for i, j in zip(blocks, blocks[1:])]
        result = sum(r / keysize for r in result) / 10
        results.append((result, keysize))
    # return min(results)[1]
    return sorted(results)[:5]
