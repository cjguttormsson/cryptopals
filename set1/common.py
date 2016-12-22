#!/usr/bin/env python3

# Common cryptographic functionality used throughout these programs
# These are all functions that have been defined throught the course of writing
# the exercises. That code is centralized here so that it may be re-used by
# other exercises without repeating it

from base64 import b64encode
from itertools import cycle
from collections import Counter
from math import sqrt

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
# TODO: change this to generate it instead of hard-coding it?
N_BITS = {0:   0, 1:   1, 2:   1, 3:   2, 4:   1, 5:   2, 6:   2, 7:   3,
          8:   1, 9:   2, 10:  2, 11:  3, 12:  2, 13:  3, 14:  3, 15:  4,
          16:  1, 17:  2, 18:  2, 19:  3, 20:  2, 21:  3, 22:  3, 23:  4,
          24:  2, 25:  3, 26:  3, 27:  4, 28:  3, 29:  4, 30:  4, 31:  5,
          32:  1, 33:  2, 34:  2, 35:  3, 36:  2, 37:  3, 38:  3, 39:  4,
          40:  2, 41:  3, 42:  3, 43:  4, 44:  3, 45:  4, 46:  4, 47:  5,
          48:  2, 49:  3, 50:  3, 51:  4, 52:  3, 53:  4, 54:  4, 55:  5,
          56:  3, 57:  4, 58:  4, 59:  5, 60:  4, 61:  5, 62:  5, 63:  6,
          64:  1, 65:  2, 66:  2, 67:  3, 68:  2, 69:  3, 70:  3, 71:  4,
          72:  2, 73:  3, 74:  3, 75:  4, 76:  3, 77:  4, 78:  4, 79:  5,
          80:  2, 81:  3, 82:  3, 83:  4, 84:  3, 85:  4, 86:  4, 87:  5,
          88:  3, 89:  4, 90:  4, 91:  5, 92:  4, 93:  5, 94:  5, 95:  6,
          96:  2, 97:  3, 98:  3, 99:  4, 100: 3, 101: 4, 102: 4, 103: 5,
          104: 3, 105: 4, 106: 4, 107: 5, 108: 4, 109: 5, 110: 5, 111: 6,
          112: 3, 113: 4, 114: 4, 115: 5, 116: 4, 117: 5, 118: 5, 119: 6,
          120: 4, 121: 5, 122: 5, 123: 6, 124: 5, 125: 6, 126: 6, 127: 7,
          128: 1, 129: 2, 130: 2, 131: 3, 132: 2, 133: 3, 134: 3, 135: 4,
          136: 2, 137: 3, 138: 3, 139: 4, 140: 3, 141: 4, 142: 4, 143: 5,
          144: 2, 145: 3, 146: 3, 147: 4, 148: 3, 149: 4, 150: 4, 151: 5,
          152: 3, 153: 4, 154: 4, 155: 5, 156: 4, 157: 5, 158: 5, 159: 6,
          160: 2, 161: 3, 162: 3, 163: 4, 164: 3, 165: 4, 166: 4, 167: 5,
          168: 3, 169: 4, 170: 4, 171: 5, 172: 4, 173: 5, 174: 5, 175: 6,
          176: 3, 177: 4, 178: 4, 179: 5, 180: 4, 181: 5, 182: 5, 183: 6,
          184: 4, 185: 5, 186: 5, 187: 6, 188: 5, 189: 6, 190: 6, 191: 7,
          192: 2, 193: 3, 194: 3, 195: 4, 196: 3, 197: 4, 198: 4, 199: 5,
          200: 3, 201: 4, 202: 4, 203: 5, 204: 4, 205: 5, 206: 5, 207: 6,
          208: 3, 209: 4, 210: 4, 211: 5, 212: 4, 213: 5, 214: 5, 215: 6,
          216: 4, 217: 5, 218: 5, 219: 6, 220: 5, 221: 6, 222: 6, 223: 7,
          224: 3, 225: 4, 226: 4, 227: 5, 228: 4, 229: 5, 230: 5, 231: 6,
          232: 4, 233: 5, 234: 5, 235: 6, 236: 5, 237: 6, 238: 6, 239: 7,
          240: 4, 241: 5, 242: 5, 243: 6, 244: 5, 245: 6, 246: 6, 247: 7,
          248: 5, 249: 6, 250: 6, 251: 7, 252: 6, 253: 7, 254: 7, 255: 8}

#########################
# BASIC TYPE TRANSFORMS #
#########################


def hex_to_bytes(s: str) -> bytes:
    """Turn a string of hex characters into a `bytes` object."""
    return bytes.fromhex(s)


# TODO: investigate if the `bytes` return object should be casted to a `str`
def hex_to_base64(s: str) -> bytes:
    """Turn a string of hex characters into a base64-encoded `bytes` object."""
    return b64encode(hex_to_bytes(s))


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
