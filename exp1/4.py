import re
import hashlib
import itertools
import datetime

# Start timing the execution
starttime = datetime.datetime.now()

# Target SHA1 hash to crack
target_hash = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

# Character variations for brute-forcing
char_variations = [
    ['Q', 'q'], ['W', 'w'], ['%', '5'], ['8', '('],
    ['=', '0'], ['I', 'i'], ['*', '+'], ['n', 'N']
]

def sha_encrypt(input_string):
    """Return the SHA1 hash of the input string."""
    sha = hashlib.sha1()
    sha.update(input_string.encode('utf-8'))
    return sha.hexdigest()

# Initialize variables for brute-forcing
initial_string = "0" * 8
current_combination = list(initial_string)

# Generate all combinations based on character variations
for a in range(2):  # For the first character
    current_combination[0] = char_variations[0][a]
    for b in range(2):  # For the second character
        current_combination[1] = char_variations[1][b]
        for c in range(2):  # For the third character
            current_combination[2] = char_variations[2][c]
            for d in range(2):  # For the fourth character
                current_combination[3] = char_variations[3][d]
                for e in range(2):  # For the fifth character
                    current_combination[4] = char_variations[4][e]
                    for f in range(2):  # For the sixth character
                        current_combination[5] = char_variations[5][f]
                        for g in range(2):  # For the seventh character
                            current_combination[6] = char_variations[6][g]
                            for h in range(2):  # For the eighth character
                                current_combination[7] = char_variations[7][h]
                                new_string = "".join(current_combination)
                                
                                # Generate permutations and check hashes
                                for perm in itertools.permutations(new_string):
                                    candidate = "".join(perm)
                                    if sha_encrypt(candidate) == target_hash:
                                        print(candidate)
                                        endtime = datetime.datetime.now()
                                        print("Time taken (seconds):", (endtime - starttime).seconds)
                                        exit(0)