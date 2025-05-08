def decrypt(ciphertext, candidate_R):
    """
    Decrypts the ciphertext given a candidate value for candidate_R.

    ciphertext: the encrypted string (obtained from the file).
    candidate_R: an integer in [0,255] which is the candidate for the RNG XOR.
    """
    if len(ciphertext) < 2:
        return None  # Not enough data to decrypt

    # The first character of ciphertext is X.
    X = ord(ciphertext[0])
    n = len(ciphertext)

    # Recover the first plaintext char:
    s_list = []
    s0 = X ^ ord(ciphertext[1])
    s_list.append(s0)

    # For further characters (except the last one)
    xor_accum = s0  # Holds s[0] XOR s[1] XOR ... (so far)
    # There are n-2 characters coming from the loop, because encryption appends one char per plaintext char except the last.
    for i in range(1, n - 1):
        # For i-th plaintext, corresponding ciphertext is at index i+1:
        current_val = X ^ ord(ciphertext[i + 1])
        # Since current_val equals (s[0] XOR ... XOR s[i]), and we already have s[0] XOR ... XOR s[i-1],
        # the i-th plaintext character is:
        s_i = current_val ^ xor_accum
        s_list.append(s_i)
        xor_accum ^= s_i

    # Recover the last plaintext character using:
    # X = candidate_R XOR (s[0] XOR s[1] ... XOR s[n-1])
    # so, s[n-1] = (candidate_R XOR X) XOR (s[0] XOR ... XOR s[n-2])
    s_last = (candidate_R ^ X) ^ xor_accum
    s_list.append(s_last)

    # Build the plaintext string
    plaintext = ''.join(chr(c) for c in s_list)
    return plaintext


def brute_force_decrypt(filename="flag.txt.out", prefix="CTFSG"):
    """
    Reads the ciphertext from file, then brute forces the candidate_R value by trying
    all values in the range 0-255 and prints the candidate plaintexts that start with the given prefix.
    """
    try:
        with open(filename, "r") as f:
            ciphertext = f.read().strip()
    except FileNotFoundError:
        print(f"Error: Could not find file {filename}")
        return

    print(f"Brute forcing decryption on ciphertext of length {len(ciphertext)} ...")
    for candidate_R in range(256):
        candidate_plaintext = decrypt(ciphertext, candidate_R)
        if candidate_plaintext and candidate_plaintext.startswith(prefix):
            print(f"[+] Found candidate_R = {candidate_R}:")
            print(candidate_plaintext)
            # If you expect only one result, you might want to return here.
            # return candidate_plaintext

    print("Brute force complete.")


if __name__ == "__main__":
    brute_force_decrypt()
