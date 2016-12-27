#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 4
# CJ Guttormsson
# 2016-12-27

from common import single_char_decode, hex_to_bytes

#################
# NEW FUNCTIONS #
#################


def find_and_decrypt_line(f_name: str) -> str:
    """Find the encrypted line in f_name and return it"""

    # Open the file and turn each line of hex into bytes
    with open(f_name) as input_file:
        possible_codes = [hex_to_bytes(line.strip()) for line in input_file]

    # Try to decode each line
    possible_plaintexts = map(single_char_decode, possible_codes)

    # Return the decoded line that looks the most like English
    return max(possible_plaintexts)[1]

########
# MAIN #
########


def main():
    f_name = '4.txt'
    plaintext = 'Now that the party is jumping\n'

    assert find_and_decrypt_line(f_name) == plaintext
    print('Challenge 4 passed successfully.')


if __name__ == '__main__':
    main()
