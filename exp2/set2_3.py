import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def generate_random_aes_key() -> bytes:
    """Generates a random 16-byte AES key."""
    return os.urandom(16)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences."""
    return bytes(x ^ y for x, y in zip(a, b))

def ecb_encrypt(block: bytes, key: bytes) -> bytes:
    """Encrypts a single block using AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def ecb_decrypt(block: bytes, key: bytes) -> bytes:
    """Decrypts a single block using AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypts the plaintext using CBC mode with the given key and IV.
    
    :param plaintext: The input data to encrypt.
    :param key: The encryption key.
    :param iv: The initialization vector.
    :return: The encrypted data (ciphertext).
    """
    block_size = AES.block_size
    plaintext = pad(plaintext, block_size)  # PKCS#7 padding
    ciphertext = b""
    previous_block = iv

    # Process each block
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        block_to_encrypt = xor_bytes(block, previous_block)
        encrypted_block = ecb_encrypt(block_to_encrypt, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext

def encryption_oracle(input_data: bytes) -> bytes:
    """
    Encrypts the input data under ECB or CBC using a randomly generated key.
    Prepends and appends 5-10 random bytes to the input before encryption.

    :param input_data: The plaintext data to encrypt.
    :return: The encrypted data (ciphertext).
    """
    # Generate a random AES key
    key = generate_random_aes_key()

    # Randomly generate 5-10 bytes to prepend and append
    prepend_bytes = os.urandom(random.randint(5, 10))
    append_bytes = os.urandom(random.randint(5, 10))

    # Combine the random bytes with the input data
    modified_data = prepend_bytes + input_data + append_bytes
    block_size = AES.block_size

    # Pad the data to a multiple of the block size
    padded_data = pad(modified_data, block_size)

    # Randomly decide whether to use ECB or CBC
    if random.randint(0, 1) == 0:
        # ECB Mode
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded_data)
        print("Encrypting with ECB")
    else:
        # CBC Mode
        iv = os.urandom(block_size)  # Random IV for CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_data)
        print("Encrypting with CBC")

    return ciphertext

def detect_block_cipher_mode(ciphertext: bytes) -> str:
    """
    Detects whether ECB or CBC mode was used based on the ciphertext.

    :param ciphertext: The encrypted data (ciphertext).
    :return: A string indicating whether ECB or CBC was used.
    """
    block_size = AES.block_size
    # Break the ciphertext into blocks of block_size
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # If there are any duplicate blocks in the ciphertext, it's likely ECB
    if len(blocks) != len(set(blocks)):
        return "ECB"
    else:
        return "CBC"

# Test the encryption oracle and detection
input_data = b"YELLOW SUBMARINE" * 4  # Input data long enough to detect ECB

ciphertext = encryption_oracle(input_data)
detected_mode = detect_block_cipher_mode(ciphertext)
print(f"Detected mode: {detected_mode}")