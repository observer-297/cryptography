import random

# Step 4: Extended Euclidean Algorithm (EGCD) and Modular Inverse
def egcd(a, b):
    """ Return g, x, y such that a*x + b*y = g = gcd(a, b) """
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x

def modinv(a, m):
    """ Return the modular inverse of a modulo m """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    else:
        return x % m

# Step 6: RSA Encryption and Decryption
def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

# Example with small primes
p = 61
q = 53

# Step 2: Compute n and totient
n = p * q
totient = (p - 1) * (q - 1)

# Step 3: Public exponent e
e = 7

# Step 4: Compute private exponent d
d = modinv(e, totient)

# Print public and private keys
print(f"Public Key: (e={e}, n={n})")
print(f"Private Key: (d={d}, n={n})")

# Step 5: Encrypt and Decrypt a message
message = 42
print(f"\nOriginal Message: {message}")

# Encrypt the message
ciphertext = rsa_encrypt(message, e, n)
print(f"Encrypted Ciphertext: {ciphertext}")

# Decrypt the message
decrypted_message = rsa_decrypt(ciphertext, d, n)
print(f"Decrypted Message: {decrypted_message}")

# Now test with larger primes using the same e = 3
def generate_prime(bits=512):
    """ Generate a random prime number of the given bit size """
    while True:
        prime_candidate = random.getrandbits(bits)
        # Ensure it's odd and greater than 1
        prime_candidate |= (1 << bits - 1) | 1
        if is_prime(prime_candidate):
            return prime_candidate

def is_prime(n, k=5):  # number of tests = k
    """ Test if a number is prime using Miller-Rabin Primality Test """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d by factoring powers of 2 from n-1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Miller-Rabin test
    def miller_test(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    for _ in range(k):
        a = random.randrange(2, n - 1)
        if not miller_test(a):
            return False
    return True

# Generate two large primes
p_large = generate_prime(512)
q_large = generate_prime(512)

# Compute n and totient for large primes
n_large = p_large * q_large
totient_large = (p_large - 1) * (q_large - 1)

# Compute private key exponent d for large primes
d_large = modinv(e, totient_large)

# Print new public and private keys
print(f"\nPublic Key (large primes): (e={e}, n={n_large})")
print(f"Private Key (large primes): (d={d_large}, n={n_large})")

# Encrypt and Decrypt a larger message (string to number conversion)
message_str = "Hello, RSA!"
message_int = int(message_str.encode('utf-8').hex(), 16)

# Encrypt the large message
ciphertext_large = rsa_encrypt(message_int, e, n_large)
print(f"Encrypted Ciphertext (large): {ciphertext_large}")

# Decrypt the large message
decrypted_message_large = rsa_decrypt(ciphertext_large, d_large, n_large)

# Convert decrypted message back to string
decrypted_message_str = bytes.fromhex(hex(decrypted_message_large)[2:]).decode('utf-8')
print(f"Decrypted Message (large): {decrypted_message_str}")