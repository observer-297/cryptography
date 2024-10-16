from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import AES
from random import Random as rand

UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = Random.new().read(16)
prefix_length = rand().randint(1, 3 * AES.block_size)  # Can occupy at most three blocks
PREFIX = Random.new().read(prefix_length)

def pad(msg):
    """Applies PKCS#7 padding to the message.

    Args:
        msg (bytes): A byte-string to pad.

    Returns:
        bytes: The padded byte-string.
    """
    length = len(msg)
    padding = AES.block_size - (length % AES.block_size)
    return msg + bytes([padding] * padding) if padding != AES.block_size else msg

def encryption_oracle(your_string):
    """Encrypts the provided string concatenated with the UNKNOWN_STRING.

    Args:
        your_string (bytes): Byte-string to prepend.

    Returns:
        bytes: The encrypted ciphertext.
    """
    msg = b'The unknown string given to you was:\n'
    plaintext = PREFIX + your_string + msg + b64decode(UNKNOWN_STRING)
    padded_plaintext = pad(plaintext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(padded_plaintext)

def detect_block_size():
    """Detects the block size used by the encryption oracle.

    Returns:
        int: The block size.
    """
    feed = b"A"
    previous_length = 0
    while True:
        cipher = encryption_oracle(feed)
        if previous_length and len(cipher) - previous_length > 1:
            return len(cipher) - previous_length
        previous_length = len(cipher)
        feed += b"A"

def detect_mode(cipher):
    """Detects whether the ciphertext was encrypted in ECB mode.

    Args:
        cipher (bytes): The ciphertext.

    Returns:
        str: 'ECB' or 'not ECB'.
    """
    chunks = [cipher[i:i + AES.block_size] for i in range(0, len(cipher), AES.block_size)]
    unique_chunks = set(chunks)

    return "ECB" if len(chunks) > len(unique_chunks) else "not ECB"

def detect_prefix_length():
    """Detects the length of the prefix used in the oracle.

    Returns:
        int: The length of the prefix.
    """
    block_size = detect_block_size()

    test_case_1 = encryption_oracle(b'a')
    test_case_2 = encryption_oracle(b'b')

    blocks = 0
    min_length = min(len(test_case_1), len(test_case_2))

    for i in range(0, min_length, block_size):
        if test_case_1[i:i + block_size] != test_case_2[i:i + block_size]:
            break
        blocks += 1

    # Calculate remaining bytes to reach the next block
    test_input = b''
    length = blocks * block_size
    for extra in range(block_size):
        test_input += b'?'
        current = encryption_oracle(test_input)[length:length + block_size]
        next = encryption_oracle(test_input + b'?')[length:length + block_size]
        if current == next:
            break

    return length + (block_size - len(test_input))

def ecb_decrypt(block_size):
    """Decrypts the plaintext using a byte-at-a-time attack.

    Args:
        block_size (int): The block size used by the encryption oracle.
    """
    common_chars = list(range(ord('a'), ord('z') + 1)) + \
                   list(range(ord('A'), ord('Z') + 1)) + \
                   [ord(' ')] + list(range(ord('0'), ord('9') + 1))
    possibilities = bytes(common_chars + [i for i in range(256) if i not in common_chars])

    plaintext = b''
    prefix_len = detect_prefix_length()
    print(f"Calculated Length of Prefix = {prefix_len}")

    check_begin = (prefix_len // block_size) * block_size
    residue = prefix_len % block_size
    check_length = block_size

    while True:
        prepend = b'A' * (block_size - 1 - (len(plaintext) + residue) % block_size)
        actual = encryption_oracle(prepend)[check_begin:check_begin + check_length]

        found = False
        for byte in possibilities:
            your_string = prepend + plaintext + bytes([byte])
            produced = encryption_oracle(your_string)[check_begin:check_begin + check_length]
            if actual == produced:
                plaintext += bytes([byte])
                found = True
                break

        if not found:
            print(f'Possible end of plaintext: No matches found.')
            print(f"Plaintext: \n{plaintext.decode('ascii')}")
            return

        if (len(plaintext) + residue) % block_size == 0:
            check_length += block_size

def main():
    block_size = detect_block_size()
    print(f"Block Size is {block_size}")

    repeated_plaintext = b"A" * 50
    cipher = encryption_oracle(repeated_plaintext)
    mode = detect_mode(cipher)
    print(f"Mode of encryption is {mode}")

    print(f"Actual size of prefix = {len(PREFIX)}")
    ecb_decrypt(block_size)

if __name__ == "__main__":
    main()