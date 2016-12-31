#!/usr/bin/env python3

# Cryptopals Challenge, Set 1, Challenge 8
# CJ Guttormsson
# 2016-12-30

from common import hex_to_bytes

#################
# NEW FUNCTIONS #
#################


def ecb_probability(ciphertext: bytes) -> float:
    """Guess the length of the repeated key used to encrypt a ciphertext."""
    blocks = [ciphertext[i*16:i*16+16] for i in range(len(ciphertext) // 16)]
    result = [hamming_distance(i, j) for i, j in zip(blocks, blocks[1:])]
    result = sum(r / 16 for r in result) / (len(ciphertext) // 16)
    # return min(results)[1]
    return result


########
# MAIN #
########


def main():
    with open('8.txt') as data_file:
        lines = [hex_to_bytes(line.strip()) for line in data_file]

    for line in lines:
        # Chunk the line in blocks of length 16 (the ECB block length).
        # If any of these chunks overlap, the text may be ECB-encrypted.
        blocks = {line[i * 16:i * 16 + 16] for i in range(len(line) // 16)}
        if len(blocks) < (len(line) // 16):
            print(len(blocks), line[:10])

    print('Challenge 8 completed successfully.')


if __name__ == '__main__':
    main()
