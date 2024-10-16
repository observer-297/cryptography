from Crypto.Cipher import AES
import base64

def main():
    encoded = []
    print('Loading file contents...')
    with open('file7.txt', 'r') as f:
        for l in f:
            encoded.append(l.rstrip())
    encoded = bytes(''.join(encoded), 'utf-8')
    encoded = base64.b64decode(encoded)
    print('Done')

    key = b'YELLOW SUBMARINE'

    cipher = AES.new(key, AES.MODE_ECB)

    decrypted = cipher.decrypt(encoded)

    print(decrypted.decode())

if __name__ == '__main__':
    main()