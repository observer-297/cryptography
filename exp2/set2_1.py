def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

data = b"YELLOW SUBMARINE"
block_size = 20

padded_data = pkcs7_pad(data, block_size)
print(padded_data)


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

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

def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypts the ciphertext using CBC mode with the given key and IV.
    
    :param ciphertext: The input data to decrypt.
    :param key: The decryption key.
    :param iv: The initialization vector.
    :return: The decrypted data (plaintext).
    """
    block_size = AES.block_size
    plaintext = b""
    previous_block = iv

    # Process each block
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = ecb_decrypt(block, key)
        plaintext_block = xor_bytes(decrypted_block, previous_block)
        plaintext += plaintext_block
        previous_block = block

    return unpad(plaintext, block_size)  # Remove PKCS#7 padding

# Test CBC encryption and decryption
key = b"YELLOW SUBMARINE"  # Example key (16 bytes for AES-128)
iv = b"\x00" * AES.block_size  # IV of all zeros

# Example plaintext (the file content or input you want to encrypt)
plaintext = b"This is a test message for CBC mode encryption."

# Encrypt the plaintext using CBC mode
ciphertext = cbc_encrypt(plaintext, key, iv)
print(f"Ciphertext (hex): {ciphertext.hex()}")

# Decrypt the ciphertext back to plaintext to verify
decrypted_text = cbc_decrypt(ciphertext, key, iv)
print(f"Decrypted text: {decrypted_text.decode()}")