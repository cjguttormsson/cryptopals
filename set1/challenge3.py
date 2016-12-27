#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 3
# CJ Guttormsson
# 2016-12-20

from common import hex_to_bytes, xor_bytes
import string
import itertools
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


#################
# NEW FUNCTIONS #
#################


def zip_dict(*dicts):
    """Zip dicts by their keys and yield tuples of the corresponding values."""
    for key in set(dicts[0]).intersection(*dicts[1:]):
        yield tuple(d[key] for d in dicts)


def english_probability(s: str) -> float:
    """determine the probability that a given ascii string is in english"""

    # Use cosine similarity to determine how much the string resembles
    # the letter distribution of English.

    # But first, if there are non-ascii characters in the result string, it is
    # certainly not English, so we can stop early
    for c in s:
        if c not in string.printable:
            return 0

    # Now, begin by making `s` into a vector of fractions, representing how
    # often each character appears. Must have the same character set as
    # CHAR_FREQ for the math to work correctly, so throw out other characters.
    cntr = Counter(c.lower() for c in s if c in CHAR_FREQ.keys())
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
            results.append((english_probability(result_ascii), result_ascii))

        except UnicodeDecodeError:
            # String couldn't even be decoded, so it definitely isn't English
            pass

    # Return only the best result, if one exists
    if len(results) > 0:
        return sorted(results, reverse=True)[0]
    else:
        return (0, '')

########
# MAIN #
########


def main():
    ciphertext = ('1b37373331363f78151b7f2b783431333d78397828372d363c783'
                  '73e783a393b3736')
    cipher_bytes = hex_to_bytes(ciphertext)
    plaintext = "Cooking MC's like a pound of bacon"

    assert single_char_decode(cipher_bytes)[1] == plaintext
    print('Challenge 3 passed successfully.')


if __name__ == '__main__':
    main()
