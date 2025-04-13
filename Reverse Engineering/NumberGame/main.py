def decode_encode(data):
    """
    Inverse of the run-length encoding:
    For every 2-character block, repeat the second character as many times as indicated by the first.
    """
    result = ""
    for i in range(0, len(data), 2):
        count = int(data[i])
        char = data[i+1]
        result += char * count
    return result

def reverse_preprocess(data):
    """
    Reverse the preprocessing: each group of 3 digits corresponds to a byte.
    """
    return bytes(int(data[i:i+3]) for i in range(0, len(data), 3))

def full_decode(encrypted_file_path, output_file_path):
    """
    Reads the encrypted file, applies 24 rounds of decoding to reverse the run-length encoding,
    then reverses the preprocessing step and writes the original flag bytes to an output file.
    """
    # Read the encrypted file (which is text)
    with open(encrypted_file_path, "r") as f:
        data = f.read().strip()

    # Reverse the 24 rounds of encoding
    for _ in range(24):
        data = decode_encode(data)

    # Reverse the preprocessing step to get the original bytes
    original_flag = reverse_preprocess(data)

    # Write the recovered flag to a new file
    with open(output_file_path, "wb") as f:
        f.write(original_flag)
    print("Decoded flag written to", output_file_path)

# Example usage:
if __name__ == "__main__":
    encrypted_file = 'flag.txt.encrypted'
    output_file = 'flag_decoded.txt'
    full_decode(encrypted_file, output_file)