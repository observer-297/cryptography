from enum import Enum

b64_encoding_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

class Status(Enum):
    """Represents the possible status of the converter
    upon finishing to read a hex character of 4 bits.
    """
    START_NEW = 0
    TAKE_2 = 1
    TAKE_4 = 2

def hex_to_base64(hexdata):
    """Returns a Base64 encoding of the given Hexadecimal string."""
    b64data = ""                # Resulting Base64 encoding
    sixbits = 0                 # Group of six bits being encoded
    status = Status.START_NEW   # Status of the conversion

    for hexchar in hexdata:
        dec = int(hexchar, 16)  # Decimal value of the character

        if status == Status.START_NEW:
            sixbits = dec
            status = Status.TAKE_2
        elif status == Status.TAKE_2:
            sixbits = (sixbits << 2) | (dec >> 2)
            b64data += b64_encoding_table[sixbits]
            sixbits = (dec & 0x3)  # Remaining 2 bits
            status = Status.TAKE_4
        elif status == Status.TAKE_4:
            sixbits = (sixbits << 4) | dec
            b64data += b64_encoding_table[sixbits]
            status = Status.START_NEW

    # Handle remaining bits and padding
    if status == Status.TAKE_2:
        sixbits <<= 2
        b64data += b64_encoding_table[sixbits] + "="
    elif status == Status.TAKE_4:
        sixbits <<= 4
        b64data += b64_encoding_table[sixbits] + "=="

    return b64data

def main():
    # Check that the method works properly
    assert hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b"
                         "65206120706f69736f6e6f7573206d757368726f6f6d") ==\
           "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

if __name__ == '__main__':
    main()