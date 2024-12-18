import base64 as b64
import sys
from itertools import chain

sys.path.insert(0, '../')

import src
from 3_3 import xor_string_with_char
from 3_3 import find_key
from 3_5 import repeat_key_xor

def decode_xor_period(s, period, start, d):
    # Decodes s at start, start+period, ...
    dec = [i for i in s]
    l = len(s)
    for i in range(start, l, period):
        dec[i] = dec[i] ^ d
    return bytes(dec)

def main():
    encoded = []
    print('Loading contents from file')
    with open('file6.txt', 'r') as f:
        for line in f:
            encoded.append(line.rstrip())
    print('Done loading')
    encoded = bytes(''.join(encoded), 'utf-8')

    # Converting to base 16
    encoded = bytes.fromhex((b64.b16encode(b64.b64decode(encoded))).decode())

    min_guess = 2
    max_guess = 40

    print(len(encoded))

    print('Guessing key size...')

    period = []
    for p in range(min_guess, max_guess+1):
        s = c = 0
        for i in range(0, len(encoded)-2*p, p):
            a = encoded[i:i+p]
            b = encoded[i+p:i+2*p]
            s += src.hamming_distance(a, b)
            c += 1
        avg = s / c
        period.append([avg / p, p])

    period.sort()

    for i in period:
        print(i)

    # Probable key length is 29
    keysize = period[0][1]
    key = []

    print('From the normalized keysize list, the probable key size is', period[0][1])

    print('Guessing the key...')
    for i in range(0, keysize):
        l = []
        concat = chain(range(32, 33), range(48, 65), range(97, 123))
        for ch in concat:
            l.append([src.score_plaintext(xor_string_with_char(encoded[i::keysize], ch)), ch])
        l.sort()
        key.append(l[0][1])

    print('The guessed key is', end=' ')
    print(''.join([chr(i) for i in key])

    # Guessing the actual key
    key = b'terminator x: bring the noise'
    print('Guessing the actual key:', key)

    print('Decoding the encoded text...\n')
    print(repeat_key_xor(encoded, key).decode())

if __name__ == '__main__':
    main()