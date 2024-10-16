from collections import OrderedDict
from Crypto.Cipher import AES
from Crypto import Random
import re

USER_DB = OrderedDict()
user_count = 0
KEY = Random.new().read(16)

class Objectify:
    """Class for creating and representing JSON-like objects from a cookie-like object."""

    def __init__(self, cookie):
        self.cookie = cookie
        self.obj = OrderedDict()

    def convert(self):
        """Converts a cookie-like object into a dictionary of key=value pairs.

        Returns:
            dict: Dictionary of key=value pairs.
        """
        if self.obj:  # Already converted
            return self.obj

        # Get key=value pairs
        kv_pairs = self.cookie.split('&')
        for pair in kv_pairs:
            k, v = pair.split('=')
            self.obj[k] = v
        return self.obj

    def __repr__(self):
        """Converts a dictionary of key=value pairs to JSON-like format for representation.

        Returns:
            str: A string formatted like a JSON object.
        """
        self.convert()
        json_repr = "{\n"
        last_key = next(reversed(self.obj))
        for key, value in self.obj.items():
            json_repr += f"\t{key}: '{value}'" + (',\n' if key != last_key else '\n')
        json_repr += "}"
        return json_repr

def pad(value, size):
    """Applies PKCS#7 padding to `value` to make it of size `size`.

    Args:
        value (bytes): A byte-string to pad.
        size (int): The required size.

    Returns:
        bytes: A byte-string = `value` + padding.
    """
    padding_length = size - len(value) % size if len(value) % size != 0 else 0
    pad_value = bytes([padding_length]) * padding_length
    return value + pad_value

def profile_for(user_info):
    """Generates an encrypted profile info for the given `user_info`.

    Args:
        user_info (str): The email address of the user.

    Returns:
        bytes: The AES-ECB encrypted profile info (email, uid, role).
    """
    global user_count
    user_info = re.sub("&|=", "", user_info)  # Sanitize `user_info`
    cookie = f"email={user_info}&uid={user_count}&role=user"
    user_count += 1

    padded_cookie = pad(cookie.encode('ascii'), AES.block_size)  # PKCS#7 padding 
    ecb_cipher = AES.new(KEY, AES.MODE_ECB)
    return ecb_cipher.encrypt(padded_cookie)

def decrypt_profile(key, cipher_cookie):
    """Decrypts the encoded ciphertext with the given `key` under AES_ECB.

    Args:
        key (bytes): The encryption key of size `AES.block_size`.
        cipher_cookie (bytes): The encrypted text.

    Returns:
        tuple: (str: The cookie-like object decrypted from `cipher_cookie`,
                 str: The JSON-like object obtained by parsing the cookie).
    """
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    plain_cookie = ecb_cipher.decrypt(cipher_cookie)

    # Remove PKCS#7 padding
    padding_length = plain_cookie[-1]
    if 0 < padding_length <= AES.block_size:
        if plain_cookie[-padding_length:] == bytes([padding_length]) * padding_length:
            plain_cookie = plain_cookie[:-padding_length]

    cookie = plain_cookie.decode('ascii')
    obj = Objectify(cookie)
    return cookie, str(obj)

def create_admin_profile():
    """Creates an `admin profile` by manipulating the encrypted profile."""
    # Create a block so that `email=<x>&uid=<x>&role=` occupies one block size
    cookie_parts = 'email=@gmail.com&uid=2&role='
    username_padding = 'A' * (AES.block_size - len(cookie_parts) % AES.block_size)
    email = username_padding + "@gmail.com"
    cipher_cookie_1 = profile_for(email)

    # Create an email that occupies one full block
    cookie_param = "email="
    hacker_email_padding = 'A' * (AES.block_size - len(cookie_param) % AES.block_size)
    admin_value = pad(b'admin', AES.block_size).decode('ascii')
    hacker_email = hacker_email_padding + admin_value
    cipher_cookie_2 = profile_for(hacker_email)

    # Concatenate the relevant blocks
    block1 = cipher_cookie_1[:-AES.block_size]  # All but the last block
    block2 = cipher_cookie_2[AES.block_size:AES.block_size * 2]  # Admin block
    cipher_block = block1 + block2 

    cookie, obj = decrypt_profile(KEY, cipher_block)
    print(f"Cookie Created: {cookie}")
    print(f"Object Created: {obj}")

if __name__ == "__main__":
    create_admin_profile()