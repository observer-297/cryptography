import itertools
import string

def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def frequency_analysis(text):
    """Perform frequency analysis on the text."""
    freq = {char: 0 for char in string.ascii_lowercase}
    for char in text.lower():
        if char in freq:
            freq[char] += 1
    return freq

def guess_key_length(ciphertext, max_length=20):
    """Guess the likely key length using the Kasiski examination method."""
    # A simple approach to find repeating sequences
    distances = {}
    for size in range(3, max_length + 1):
        for i in range(len(ciphertext) - size):
            seq = ciphertext[i:i + size]
            if seq in distances:
                distances[seq].append(i)
            else:
                distances[seq] = [i]

    # Calculate distances between repeating sequences
    distances = {k: [j - i for i, j in itertools.combinations(v, 2)] for k, v in distances.items() if len(v) > 1}
    
    # Flatten the list of distances and count occurrences
    distance_counts = {}
    for dist_list in distances.values():
        for dist in dist_list:
            if dist in distance_counts:
                distance_counts[dist] += 1
            else:
                distance_counts[dist] = 1

    # Return the most common distances
    return sorted(distance_counts.items(), key=lambda item: item[1], reverse=True)

def break_xor_cipher(ciphertext, key_length):
    """Attempt to break the XOR cipher by guessing the key."""
    # Split the ciphertext into blocks
    blocks = [ciphertext[i::key_length] for i in range(key_length)]
    key = bytearray()

    for block in blocks:
        # Frequency analysis on the block
        freq = frequency_analysis(block)
        # Guess the key byte based on the most common character
        most_common_char = max(freq, key=freq.get)
        key_byte = ord(most_common_char) ^ ord('e')  # Assuming 'e' is the most common char in English
        key.append(key_byte)

    return bytes(key)

def decrypt(ciphertext, key):
    """Decrypt the ciphertext using the key."""
    return xor_bytes(ciphertext, itertools.cycle(key))

def main():
    # Example ciphertext (replace with your own)
    ciphertext = b'\x1b\x0e\x0c\x0b\x0a\x0d\x1c\x1d\x1f\x1b\x08\x0e'  # Sample XORed ciphertext
    max_key_length = 20
    
    # Guess the key length
    key_lengths = guess_key_length(ciphertext, max_key_length)
    print("Guessed Key Lengths:", key_lengths)

    # For demonstration, we'll take the most common guessed length
    if key_lengths:
        likely_key_length = key_lengths[0][0]
        print(f"Trying key length: {likely_key_length}")

        # Break the cipher
        key = break_xor_cipher(ciphertext, likely_key_length)
        print("Guessed Key:", key)

        # Decrypt the ciphertext
        plaintext = decrypt(ciphertext, key)
        print("Decrypted Plaintext:", plaintext)

if __name__ == "__main__":
    main()