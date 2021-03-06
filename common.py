#!/usr/bin/env python3

# Common cryptographic functionality used throughout these programs
# These are all functions that have been defined throught the course of writing
# the exercises. That code is centralized here so that it may be re-used by
# other exercises without repeating it

from base64 import b64encode, b64decode
from itertools import cycle
from collections import Counter
from math import sqrt
import string
import itertools
from Crypto.Cipher import AES
import random

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


def base64_to_bytes(s: str) -> bytes:
    """Turn a base64-encoded string into a decoded `bytes` object."""
    return b64decode(s)


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


def pkcs7_pad(text: bytes, pad_len: int = 16) -> bytes:
    """Pad out some text to a multiple of pad_len bytes"""
    extra_len = (pad_len - (len(text) % pad_len)) % pad_len
    return text + bytes([extra_len] * extra_len)


#####################
# RANDOM ALGORITHMS #
#####################


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


############
# GUESSERS #
############

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


def is_ecb(data: bytes) -> bool:
    """Guess if the given ciphertext was encrypted in ECB mode."""
    # Split the text into chunks. If any of those chunks are the same,
    # it is likely that ECB was used to encrypt the text.
    blocks = {data[i * 16:i * 16 + 16] for i in range(len(data) // 16)}
    return len(blocks) < (len(data) // 16)


def guess_mode(alg) -> str:
    """Guess if the given encryption algorithm is running in ECB or CBC mode"""
    plaintext = b'e'*48
    if is_ecb(alg(plaintext)):
        return 'ECB'
    else:
        return 'CBC'


##############
# AES CRYPTO #
##############


def aes_128_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    """Take a stream of encrypted bytes and decrypt them with the key."""
    # The key must be 128 bits (16 bytes) long
    assert len(key) == 16

    # Set up the cipher and perform the decryption. No salt or IV.
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def aes_128_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    """Take a stream of un-encrypted bytes and encrypt them with the key."""
    # Make sure the data and key are the correct lengths
    assert len(key) == 16
    data = pkcs7_pad(data)

    # Set up the cipher and perform the encryption. No salt or IV.
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def aes_128_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt a stream of cbc-encrypted bytes with the key."""
    assert len(key) == 16

    # xor each decrypted block with the previous encrypted block
    return xor_bytes(aes_128_ecb_decrypt(data, key), (b'\0' * 16) + data[:-16])


def aes_128_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt a stream of bytes with the key using block chaining."""
    # Make sure the data and key are the correct lengths
    assert len(key) == 16
    data = pkcs7_pad(data)

    # Create an output buffer for blocks and add to it one at a time
    # The buffer is initialized with the IV.
    buf = [b'\0' * 16]
    for block in [data[i:i+16] for i in range(0, len(data), 16)]:
        buf.append(aes_128_ecb_encrypt(xor_bytes(block, buf[-1]), key))

    # Combine encrypted block back together, ignoring the IV
    return b''.join(buf[1:])


###################
# OTHER UTILITIES #
###################

def zip_dict(*dicts):
    """Zip dicts by their keys and yield tuples of the corresponding values."""
    for key in set(dicts[0]).intersection(*dicts[1:]):
        yield tuple(d[key] for d in dicts)


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

