#!/usr/bin/env python3

# Cryptopals Challenge, Set 2, Challenge 13
# CJ Guttormsson
# 2017-01-20

import sys
sys.path.append('..')
from common import get_random_key, aes_128_ecb_encrypt, aes_128_ecb_decrypt


#############
# CONSTANTS #
#############


# A random but constant key
UNKNOWN_KEY = get_random_key()


#################
# NEW FUNCTIONS #
#################


def parse_cookie(cookie: str):
	"""Take a str encoded like "key1=val1&key2=val2" and turn it into a dict"""
	return dict(pair.split('=') for pair in cookie.split('&'))


def profile_for(email: str):
	"""Take an email string and generate an user profile dict from it."""
	safe_email = ''.join(c for c in email if c not in '&=')
	return 'email={}&uid=10&role=user'.format(safe_email)


def get_encrypted_profile(email: str) -> bytes:
	"""Generate a profile for the given email, and encrypt it."""
	return aes_128_ecb_encrypt(profile_for(email).encode('utf-8'), UNKNOWN_KEY)


def decrypt_and_parse_profile(encrypted_profile: bytes): # dict
	"""Take a profile encrypted with UNKNOWN_KEY, decrypt it, and parse it."""
	decrypted_profile = aes_128_ecb_decrypt(encrypted_profile, UNKNOWN_KEY)
	decoded_profile = decrypted_profile.decode('utf-8')
	return parse_cookie(decoded_profile)


########
# MAIN #
########


if __name__ == '__main__':
	print(profile_for('cjgj@google.com'))
	print(profile_for('cjgj@google.com&role=admin'))
	enc_prof = get_encrypted_profile('___e@ma.il')
	print(enc_prof)
	print(decrypt_and_parse_profile(enc_prof))