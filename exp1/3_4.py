import src
import 3_3

def is_alpha(s):
    # Check if the Unicode value of all characters is less than 128
    return all(b < 128 for b in s)

def main():
    encoded = []
    print("Loading contents from file...")
    with open('file4.txt', 'rt') as f:
        encoded = [bytes.fromhex(line.rstrip()) for line in f]
    print("Done loading.")

    decoded = []
    print("Brute forcing all possible combinations...")
    for e in encoded:
        for i in range(256):
            decoded.append(c3.xor_string_with_char(e, i))
    print("Done.")

    print("Finding probable decoded strings...")
    probable_decoded = []
    for d in decoded:
        if is_alpha(d):
            score = src.score_plaintext(d)
            if score < 50 and src.percentage_alpha(d) > 60:
                probable_decoded.append((score, d.decode('utf-8', 'ignore')))
    print("Done.")

    print("Generating probable decoded strings...")
    probable_decoded.sort()
    for score, decoded_str in probable_decoded:
        print(score, ":", decoded_str)
    print("Done!")

if __name__ == '__main__':
    main()