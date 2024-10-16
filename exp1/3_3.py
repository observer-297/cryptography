import src

def xor_string_with_char(s, c):
    # Each character of s is XORed with c (in ASCII)
    return bytes([i ^ c for i in s])

def find_key(s):
    # Find the character XORed to produce s
    scores = [src.score_plaintext(xor_string_with_char(s, i)) for i in range(256)]
    key = scores.index(min(scores))
    return key

def main():
    # Encoded string
    encoded = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    key = find_key(encoded)
    print("Key is", hex(key))
    print("Decoded string is:", xor_string_with_char(encoded, key).decode())

if __name__ == '__main__':
    main()