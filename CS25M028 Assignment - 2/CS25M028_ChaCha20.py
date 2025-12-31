import os
import struct
import binascii
import time

# Key must be a 64-character hexadecimal string (32 bytes).
KEY_HEX = 0xcb89e85f76dcb4bf01df2216758455a28e722a9ca17397c972138dd9c0c2101c

# Nonce must be 12 bytes.
NONCE_BYTES = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# --- File Paths ---
# Path to the .zip file you want to encrypt.
FILE_TO_ENCRYPT = r"C:\Users\majji\OneDrive\Desktop\mtech_learninng\Applied_cryptography\CS25M028_Assignment_2\FileToEncrypt.zip"
# Where to save the encrypted .bin file.
ENCRYPTED_OUTPUT_FILE = "CS25M028_Encrypted.bin"

# Path to the .bin file you want to decrypt.
FILE_TO_DECRYPT = r"C:\Users\majji\OneDrive\Desktop\mtech_learninng\Applied_cryptography\Encrypted.bin"
# Where to save the decrypted .zip file.
DECRYPTED_OUTPUT_FILE = "CS25M049_Decrypted.zip"

#     2. CORE CHACHA20 IMPLEMENTATION ---
# This section contains the cryptographic logic.

def rotl(x, n):
    """Performs a 32-bit left rotation."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def quarter_round(a, b, c, d):
    """Performs a ChaCha20 quarter round on four 32-bit integers."""
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl(b, 7)
    return a, b, c, d

def chacha20_block(key, nonce, counter):
    """Generates one 64-byte (512-bit) keystream block."""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    k = list(struct.unpack('<8L', key))
    n = list(struct.unpack('<3L', nonce))
    c = [counter]
    initial_state = [
        constants[0], constants[1], constants[2], constants[3],
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
        c[0], n[0], n[1], n[2]
    ]
    state = list(initial_state)
    for _ in range(10):
        state[0], state[4], state[8], state[12] = quarter_round(state[0], state[4], state[8], state[12])
        state[1], state[5], state[9], state[13] = quarter_round(state[1], state[5], state[9], state[13])
        state[2], state[6], state[10], state[14] = quarter_round(state[2], state[6], state[10], state[14])
        state[3], state[7], state[11], state[15] = quarter_round(state[3], state[7], state[11], state[15])
        state[0], state[5], state[10], state[15] = quarter_round(state[0], state[5], state[10], state[15])
        state[1], state[6], state[11], state[12] = quarter_round(state[1], state[6], state[11], state[12])
        state[2], state[7], state[8], state[13] = quarter_round(state[2], state[7], state[8], state[13])
        state[3], state[4], state[9], state[14] = quarter_round(state[3], state[4], state[9], state[14])
    final_state = [(initial_state[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return b''.join([struct.pack('<L', x) for x in final_state])

def chacha20_crypt(key, nonce, data, initial_counter=0):
    """Encrypts or decrypts data using ChaCha20."""
    output = bytearray()
    counter = initial_counter
    for i in range(0, len(data), 64):
        keystream_block = chacha20_block(key, nonce, counter)
        block = data[i:i+64]
        encrypted_block = bytes([block[j] ^ keystream_block[j] for j in range(len(block))])
        output.extend(encrypted_block)
        counter += 1
    return bytes(output)


def encrypt_file():
    """Encrypts the file specified in the configuration."""
    print(f"--- Starting Encryption ---")
    
    # Validate key length before conversion.
    if len(KEY_HEX) != 64:
        print(f" ERROR: KEY_HEX must be 64 hex characters (32 bytes).")
        return
        
    # Attempt to convert hex key. Will crash with binascii.Error on invalid hex.
    key_bytes = bytes.fromhex(KEY_HEX)
        
    # Check if the input file exists before trying to open it.
    if not os.path.exists(FILE_TO_ENCRYPT):
        print(f" ERROR: Input file not found at '{FILE_TO_ENCRYPT}'")
        return
        
    print(f"  > Reading input file: '{FILE_TO_ENCRYPT}'")
    with open(FILE_TO_ENCRYPT, 'rb') as f:
        input_data = f.read()
    
    start_time = time.time()
    encrypted_data = chacha20_crypt(key_bytes, NONCE_BYTES, input_data)
    end_time = time.time()
    
    print(f"  > Encryption finished in {end_time - start_time:.4f} seconds.")
    
    with open(ENCRYPTED_OUTPUT_FILE, 'wb') as f:
        f.write(encrypted_data)
    print(f" SUCCESS: Encrypted file saved to '{ENCRYPTED_OUTPUT_FILE}'")


def decrypt_file():
    """Decrypts the file specified in the configuration."""
    print(f"--- Starting Decryption ---")
    
    # Validate key length before conversion.
    if len(KEY_HEX) != 64:
        print(f" ERROR: KEY_HEX must be 64 hex characters (32 bytes).")
        return

    # Attempt to convert hex key. Will crash with binascii.Error on invalid hex.
    key_bytes = binascii.unhexlify(KEY_HEX)
        
    # Check if the input file exists before trying to open it.
    if not os.path.exists(FILE_TO_DECRYPT):
        print(f" ERROR: Input file not found at '{FILE_TO_DECRYPT}'")
        return
        
    print(f"  > Reading input file: '{FILE_TO_DECRYPT}'")
    with open(FILE_TO_DECRYPT, 'rb') as f:
        input_data = f.read()
        
    start_time = time.time()
    decrypted_data = chacha20_crypt(key_bytes, NONCE_BYTES, input_data)
    end_time = time.time()
    
    print(f"  > Decryption finished in {end_time - start_time:.4f} seconds.")

    with open(DECRYPTED_OUTPUT_FILE, 'wb') as f:
        f.write(decrypted_data)
    print(f" SUCCESS: Decrypted file saved to '{DECRYPTED_OUTPUT_FILE}'")


if __name__ == '__main__':
    print("--- ChaCha20 Hardcoded File Tool ---")    
    encrypt_file()
    #decrypt_file()