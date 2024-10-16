def repeat_key_xor(s, key):
    # Returns s by repeatedly XORing it with key
    ans = [s[i] ^ key[i % len(key)] for i in range(len(s))]
    return bytes(ans)

def main():
    encoded = b'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    key = b'ICE'

    assert repeat_key_xor(encoded, key).hex() == ('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263'
                                                  '24272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b202831'
                                                  '65286326302e27282f')

if __name__ == '__main__':
    main()