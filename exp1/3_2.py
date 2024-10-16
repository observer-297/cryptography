def xor_hex_string(HEX1, HEX2):
    # Returns XOR of two hex equivalent strings as hex equivalent string
    return bytes([hex1 ^ hex2 for hex1, hex2 in zip(HEX1, HEX2)])

def main():
    # Inputs
    HEX1 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    HEX2 = bytes.fromhex('686974207468652062756c6c277320657965')

    # Output
    XOR_HEX = xor_hex_string(HEX1, HEX2)

    assert XOR_HEX.hex() == '746865206b696420646f6e277420706c6179'

if __name__ == '__main__':
    main()