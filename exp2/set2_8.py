from Crypto.Cipher import AES
from Crypto import Random
import re


def pad(value, size):
    """Applies PKCS#7 padding to `value` to make it of size `size`.

    Args:
        value (bytes): A byte-string to pad.
        size (int): The required size.

    Returns:
        bytes: A byte-string = `value` + padding.
    """
    padding_length = size - len(value) % size
    return value + bytes([padding_length] * padding_length) if padding_length < size else value


class InvalidPaddingError(Exception):
    """Exception raised for invalid PKCS#7 padding."""
    def __init__(self, padded_msg, message="has invalid PKCS#7 padding."):
        self.padded_msg = padded_msg
        self.message = message
        super().__init__(self.message)

    def __repr__(self):
        return f"{self.padded_msg} {self.message}"


def valid_padding(padded_msg, block_size):
    """Checks if `padded_msg` has valid PKCS#7 padding.

    Args:
        padded_msg (bytes): The padded text.
        block_size (int): The block size.

    Returns:
        bool: True if valid, False otherwise.
    """
    if len(padded_msg) % block_size != 0:
        return False

    last_byte = padded_msg[-1]
    if last_byte < 1 or last_byte > block_size:
        return False

    if padded_msg[-last_byte:] != bytes([last_byte] * last_byte:
        return False

    return padded_msg[:-last_byte].decode('ascii', errors='ignore').isprintable()


def remove_padding(padded_msg, block_size):
    """Removes padding from `padded_msg`.

    Args:
        padded_msg (bytes): The padded message.
        block_size (int): The block size.

    Raises:
        InvalidPaddingError: If the padding is invalid.

    Returns:
        bytes: The unpadded message.
    """
    if not valid_padding(padded_msg, block_size):
        raise InvalidPaddingError(padded_msg)
    return padded_msg[:-padded_msg[-1]]


QUOTE = {b';': b'%3B', b'=': b'%3D'}
KEY = Random.new().read(AES.block_size)
IV = bytes(AES.block_size)  # Initialization vector of all zeros


def cbc_encrypt(input_text):
    """Encrypts `input_text` using AES-128 in CBC mode.

    Args:
        input_text (bytes): The input to encrypt.

    Returns:
        bytes: The AES-128-CBC encrypted result.
    """
    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"

    for key, value in QUOTE.items():
        input_text = re.sub(key, value, input_text)

    plaintext = pad(prepend + input_text + append, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(plaintext)


def check(ciphertext):
    """Checks if decrypted `ciphertext` contains `;admin=true;`.

    Args:
        ciphertext (bytes): The encrypted text.

    Returns:
        bool: True if contains `;admin=true;`, False otherwise.
    """
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    return b";admin=true;" in plaintext


def test():
    """Tests the injection of `;admin=true;` into the ciphertext."""
    input_string = b'A' * AES.block_size * 2
    ciphertext = cbc_encrypt(input_string)

    required = pad(b";admin=true;", AES.block_size)
    inject = bytes(r ^ ord('A') for r in required)

    extra = len(ciphertext) - len(inject) - 2 * AES.block_size
    inject = bytes(2 * AES.block_size) + inject + bytes(extra)

    crafted = bytes(x ^ y for x, y in zip(ciphertext, inject))

    if check(crafted):
        print("Admin Found")
    else:
        print("Admin Not Found")


if __name__ == "__main__":
    test()