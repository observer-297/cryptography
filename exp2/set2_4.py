from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import AES

UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = Random.new().read(16)

def pad(your_string, msg):
 
    paddedMsg = your_string + msg

    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg

    padding = size - (length % size)
    padValue = bytes([padding])
    paddedMsg += padValue * padding

    return paddedMsg


def encryption_oracle(your_string):
   
   # msg = bytes('The unknown string given to you was:\n', 'ascii')
    # append the `UNKNOWN_STRING` given to us to the `msg`
    #plaintext = msg + b64decode(UNKNOWN_STRING)
    plaintext = b64decode(UNKNOWN_STRING)
    # add `your_string` to prepend to `plaintext` and apply `PKCS#7` padding to correct size
    paddedPlaintext = pad(your_string, plaintext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(paddedPlaintext)

    return ciphertext

"""using the managable string before the unkown 
increase the len of managable string bit by bit,when the len of managable string and unkown encrypted changes,that means the number of block changes,then the blocking size is the changed len substract the before len;
"""
def detect_block_size():
    
    feed = b"A"
    length = 0
    while True:
        cipher = encryption_oracle(feed)
        # on every iteration, add one more character
        feed += feed
        # if the length of the ciphertext increases by more than 1,feed += feed
        # PKCS#7 padding must have been added to make the size of plaintext == block_size
        # increase in the size gives the value of block_size
        if not length == 0 and len(cipher) - length > 1:
            return len(cipher) - length
        length = len(cipher)


def detect_mode(cipher):
    
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i+chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"
    return "not ECB"


def ecb_decrypt(block_size):
  
    # common = lower_cases + upper_cases + space + numbers
    # to optimize brute-force approach
    common = list(range(ord('a'), ord('z'))) + list(range(ord('A'),
                                                          ord('Z'))) + [ord(' ')] + list(range(ord('0'), ord('9')))
    rare = [i for i in range(256) if i not in common]
    possibilities = bytes(common + rare)

    plaintext = b''  # holds the entire plaintext = sum of `found_block`'s
    check_length = block_size

    while True:
        # as more characters in the block are found, the number of A's to prepend decreases
        prepend = b'A' * (block_size - 1 - (len(plaintext) % block_size))
        actual = encryption_oracle(prepend)[:check_length]
"""how to get the every bit after knowing the blocking size: the len of managabled string changes from blocksize-1,0;by constrasting the result of e1:managabled string+plain+unkown[:blocksize] and e2: managabled string+plain+one bit guessed[:blocksize];when e1==e2,then managabled string substrcats,plain+=one bit
"""
        found = False
        for byte in possibilities:
            value = bytes([byte])
            your_string = prepend + plaintext + value
            produced = encryption_oracle(your_string)[:check_length]
            if actual == produced:
                plaintext += value
                found = True
                break

        if not found:
            print(f'Possible end of plaintext: No matches found.')
            print(f"Plaintext: \n{ plaintext.decode('ascii') }")
            return

        if len(plaintext) % block_size == 0:
            check_length += block_size


def main():
    # detect block size
    block_size = detect_block_size()
    print(f"Block Size is { block_size }")

    # detect the mode (should be ECB)
    repeated_plaintext = b"A" * 50
    cipher = encryption_oracle(repeated_plaintext)
    mode = detect_mode(cipher)
    print(f"Mode of encryption is { mode }")

    # decrypt the plaintext inside `encryption_oracle()`
    ecb_decrypt(block_size)


if __name__ == "__main__":
    main()
