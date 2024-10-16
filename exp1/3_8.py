import base64
from Crypto.Cipher import AES

def main():
    encoded = []
    print('Reading contents from file...')
    with open('file8.txt', 'r') as f:
        for l in f:
            encoded.append(l.rstrip())
    encoded = [bytes.fromhex(e) for e in encoded]
    print('Done')

    print('Finding ciphertext with repeated blocks of the same text...')
    line_number = 1
    for e in encoded:
        for i in range(0, len(e), 16):
            for j in range(i + 16, len(e), 16):
                if e[i:i + 16] == e[j:j + 16]:
                    print(f"Repeated block found in line {line_number}")
        line_number += 1

if __name__ == '__main__':
    main()