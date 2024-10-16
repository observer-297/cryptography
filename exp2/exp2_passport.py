from Crypto.Cipher import AES
import base64
import binascii
from hashlib import sha1

def jiou(ka):
    k = []
    a = bin(int(ka, 16))[2:].zfill(56)  # Ensure 56 bits
    for i in range(0, len(a), 8):
        if a[i:i + 7].count('1') % 2 == 0:
            k.append(a[i:i + 7] + '1')
        else:
            k.append(a[i:i + 7] + '0')
    return hex(int(''.join(k), 2))[2:]

def calculate_check_digit(a, b):
    c = 0
    for i in range(len(a)):
        c += a[i] * b[i]
        c %= 10
    return c

def generate_key(passport):
    no = passport[:10]
    birth = passport[13:20]
    arrive = passport[21:28]
    mrz = no + birth + arrive
    h_mrz = sha1(mrz.encode()).hexdigest()
    
    k_seed = h_mrz[:32]
    c = '00000001'
    d = k_seed + c
    h_d = sha1(bytes.fromhex(d)).hexdigest()
    
    ka = jiou(h_d[:16])
    kb = jiou(h_d[16:32])
    return ka + kb

def decrypt_aes(cipher_text, key):
    cipher_bytes = base64.b64decode(cipher_text)
    aes = AES.new(bytes.fromhex(key), AES.MODE_CBC, bytes.fromhex('0' * 32))
    return aes.decrypt(cipher_bytes).decode()

# Step 1
a = [1, 1, 1, 1, 1, 6]
b = [7, 3, 1, 7, 3, 1]
check_digit = calculate_check_digit(a, b)
print(f'Check Digit: {check_digit}')  # Example output

# Step 2-5
passport = '12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4'
key = generate_key(passport)
cipher_text = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
result = decrypt_aes(cipher_text, key)
print(result)