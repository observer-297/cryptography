def valid_padding(padded_msg, block_size):
    """Checks if `padded_msg` has valid PKCS#7 padding for the given `block_size`.

    Args:
        padded_msg (bytes): The padded text.
        block_size (int): The block size that is to be obtained by padding.

    Returns:
        bool: True if the padding is valid, False otherwise.
    """
    # Check if the length of `padded_msg` is a multiple of `block_size`
    if len(padded_msg) % block_size != 0:
        return False

    last_byte = padded_msg[-1]

    # Check if the last byte value is valid
    if last_byte < 1 or last_byte > block_size:
        return False

    # Check if padding bytes are all the same
    padding = padded_msg[-last_byte:]
    if padding != bytes([last_byte]) * last_byte:
        return False

    # Ensure remaining characters are printable
    if not padded_msg[:-last_byte].decode('ascii', errors='ignore').isprintable():
        return False

    return True


def remove_padding(padded_msg, block_size):
    """Removes padding from `padded_msg`, raises an error if padding is invalid.

    Args:
        padded_msg (bytes): The message that is padded using PKCS#7 padding.
        block_size (int): The block size that is obtained by said padding.

    Raises:
        ValueError: If the padding is invalid.
    """
    if not valid_padding(padded_msg, block_size):
        raise ValueError(f"{padded_msg} has invalid PKCS#7 padding.")

    last_byte = padded_msg[-1]
    unpadded = padded_msg[:-last_byte]
    print(f"Padding removed successfully...")
    print(f"Before padding removal: {padded_msg}")
    print(f"After padding removal: {unpadded}")


def test():
    """Tests the `remove_padding()` function with various test cases."""
    block_size = 16

    test_cases = [
        (b'ICE ICE BABY\x03\x03\x03\x03', "Incorrect value < required"),
        (b"ICE ICE BABY\x05\x05\x05\x05", "Incorrect value > required"),
        (b"ICE ICE BABY\x04\x04\x04", "Incorrect length"),
        (b"ICE ICE BABY\x01\x02\x03\x04", "Variable numbers"),
        (b"ICE ICE BABY\x04\x04\x04\x04", "Correct padding"),
    ]

    for padded_msg, description in test_cases:
        print(f"Testing: {description}")
        try:
            remove_padding(padded_msg, block_size)
        except ValueError as e:
            print(e)


if __name__ == "__main__":
    test()