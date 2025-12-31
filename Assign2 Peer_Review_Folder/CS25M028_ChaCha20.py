

import struct
import time
import os
import binascii

# Global logger list to store log messages
LOG_MESSAGES = []

def log(message):
    """Appends a message to the global log list."""
    LOG_MESSAGES.append(message)

def rotl(x, n):
    """Performs a 32-bit left rotation."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def quarter_round(a, b, c, d, log_enabled=False):
    """ Performs a ChaCha20 quarter round on four 32-bit integers.
    The operations and rotation constants are different from Salsa20. """
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl(d, 16)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl(b, 12)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = rotl(d, 8)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = rotl(b, 7)
    if log_enabled:
        log(f"    QR Output: a={a:08x}, b={b:08x}, c={c:08x}, d={d:08x}")
    return a, b, c, d

def format_state(state):
    """ Formats the 16-element state matrix for logging. """
    return "\n".join([f"    {state[i]:08x} {state[i+1]:08x} {state[i+2]:08x} {state[i+3]:08x}" for i in range(0, 16, 4)])

def chacha20_block(key, nonce, counter, log_enabled=False):
    """ Generates one 64-byte (512-bit) keystream block. """
    # 1. Initial State Setup
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    k = list(struct.unpack('<8L', key))
    n = list(struct.unpack('<3L', nonce)) # ChaCha20 uses a 12-byte nonce
    c = list(struct.unpack('<1L', counter.to_bytes(4, 'little'))) # and a 4-byte counter

    # Initial 4x4 state matrix for ChaCha20
    initial_state = [
        constants[0], constants[1], constants[2], constants[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        c[0], n[0], n[1], n[2]
    ]
    
    state = list(initial_state)
    if log_enabled:
        log("\n--- ChaCha20 Block Generation ---")
        log(f"Initial State (Key, Nonce, Counter):")
        log(format_state(state))
        
    # 2. 20 Rounds (10 double rounds) of computation
    for i in range(10):
        if log_enabled:
            log(f"\n-- Double Round {i+1}/10 --")

        # Column Round 
        if log_enabled: log("  Column Round:")
        state[0], state[4], state[8], state[12] = quarter_round(state[0], state[4], state[8], state[12], log_enabled)
        state[1], state[5], state[9], state[13] = quarter_round(state[1], state[5], state[9], state[13], log_enabled)
        state[2], state[6], state[10], state[14] = quarter_round(state[2], state[6], state[10], state[14], log_enabled)
        state[3], state[7], state[11], state[15] = quarter_round(state[3], state[7], state[11], state[15], log_enabled)
        if log_enabled:
            log("  State after Column Round:")
            log(format_state(state))

        # Diagonal Round
        if log_enabled: log("  Diagonal Round:")
        state[0], state[5], state[10], state[15] = quarter_round(state[0], state[5], state[10], state[15], log_enabled)
        state[1], state[6], state[11], state[12] = quarter_round(state[1], state[6], state[11], state[12], log_enabled)
        state[2], state[7], state[8], state[13] = quarter_round(state[2], state[7], state[8], state[13], log_enabled)
        state[3], state[4], state[9], state[14] = quarter_round(state[3], state[4], state[9], state[14], log_enabled)
        if log_enabled:
            log("  State after Diagonal Round: ")
            log(format_state(state))

    # 3. Final Addition
    final_state = [(initial_state[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    if log_enabled:
        log("\nFinal State (after addition):")
        log(format_state(final_state))

    # 4. Serialize to a 64-byte block
    keystream_block = b''.join([struct.pack('<L', x) for x in final_state])
    if log_enabled:
        log(f"\n Generated 64-byte Keystream Block: {binascii.hexlify(keystream_block).decode('ascii')}")

    return keystream_block

def chacha20_crypt(key, nonce, plaintext, initial_counter=0):
    """  Encrypts or decrypts a plaintext using ChaCha20. """
    ciphertext = bytearray()
    counter = initial_counter
    
    for i in range(0, len(plaintext), 64):
        keystream_block = chacha20_block(key, nonce, counter)
        block = plaintext[i:i+64]
        
        encrypted_block = bytes([block[j] ^ keystream_block[j] for j in range(len(block))])
        ciphertext.extend(encrypted_block)
        
        counter += 1
        
    return bytes(ciphertext)

def run_chacha20_assignment(roll_no, log_switch):
    """ Main function to run all parts of the ChaCha20 assignment."""
    global LOG_MESSAGES
    LOG_MESSAGES = [] # Clear logs for this run
    
    print(" Running ChaCha20 Assignment ")
    
    #  Part 1: Diffusion Analysis 
    print("Part 1: Performing diffusion analysis...")
    log(" CS6530 Applied Cryptography - Assignment 1 - ChaCha20 Analysis ")
    log(f"Roll Number: {roll_no}\n")
    
    key = b'\x00' * 32
    nonce = b'\x00' * 12  # ChaCha20 has a 12-byte nonce
    
    log("Analysis for Counter values 0 and 1")
    log("Key: all zeros, Nonce: all zeros")
    log(f"\n COUNTER 0 ")
    chacha20_block(key, nonce, 0, log_enabled=log_switch)
    log(f"\n--- COUNTER 1 ---")
    chacha20_block(key, nonce, 1, log_enabled=log_switch)
    
    roll_no_val = int(''.join(filter(str.isdigit, roll_no))[-2:])
    log(f"\n Analysis for Counter values {roll_no_val} and {roll_no_val + 1} ")
    log("Key: all zeros, Nonce: all zeros")
    log(f"\n--- COUNTER {roll_no_val} ---")
    chacha20_block(key, nonce, roll_no_val, log_enabled=log_switch)
    log(f"\n--- COUNTER {roll_no_val + 1} ---")
    chacha20_block(key, nonce, roll_no_val + 1, log_enabled=log_switch)
    
    part1_output_file = f"{roll_no}_CS6530_Assgn1_Part1_ChaCha20.txt"
    with open(part1_output_file, 'w') as f:
        f.write("\n".join(LOG_MESSAGES))
    print(f"Part 1 analysis saved to {part1_output_file}")
    print(f"File size: {os.path.getsize(part1_output_file)} bytes ")

    #  Part 2: File Encryption/Decryption 
    print("\nPart 2: Performing file encryption and decryption...")
    plaintext_file = part1_output_file
    encrypted_file = f"{roll_no}_CS6530_Assgn1_Part1_ChaCha20_Encrypted.bin"
    decrypted_file = f"{roll_no}_CS6530_Assgn1_Part1_ChaCha20_decrypted.txt"
    
    file_key = b'MySecretKeyForFileEncryption1234'
    file_nonce = b'MyChaNonce12' # 12 bytes
    
    with open(plaintext_file, 'rb') as f:
        plaintext_data = f.read()

    # Encryption
    start_time = time.time()
    encrypted_data = chacha20_crypt(file_key, file_nonce, plaintext_data)
    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"Encryption completed in {encryption_time:.6f} seconds. ")
    
    with open(encrypted_file, 'wb') as f:
        f.write(encrypted_data)
    print(f"Encrypted file saved to {encrypted_file}")
    print(f"File size: {os.path.getsize(encrypted_file)} bytes ")

    # Decryption
    start_time = time.time()
    decrypted_data = chacha20_crypt(file_key, file_nonce, encrypted_data)
    end_time = time.time()
    decryption_time = end_time - start_time
    print(f"Decryption completed in {decryption_time:.6f} seconds. ")
    
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted_data)
    print(f"Decrypted file saved to {decrypted_file}")
    
    if plaintext_data == decrypted_data:
        print("Verification successful: Original and decrypted files are identical.")
    else:
        print("Verification FAILED: Original and decrypted files differ.")

    #  Part 3: Performance Analysis
    print("\n Part 3: Performing performance analysis...")
    if log_switch:
        print("WARNING: Log switch is ON. Performance measurement will be inaccurate.")
        
    perf_data = b'\x00' * (1024 * 1024) # 1 MB of data
    
    start_time = time.time()
    chacha20_crypt(key, nonce, perf_data)
    end_time = time.time()
    
    perf_time = end_time - start_time
    speed_mb_s = (len(perf_data) / (1024 * 1024)) / perf_time
    
    print(f"ChaCha20 performance: Encrypted 1 MB in {perf_time:.6f} seconds.")
    print(f"Approximate speed: {speed_mb_s:.2f} MB/s")
    print("Compare this with the performance of the reference C implementation.s")
    print("-" * 30 + "\n")
    
if __name__ == '__main__':
    MY_ROLL_NO = "CS25M028"
    LOG_CORE_STATE = True
    run_chacha20_assignment(MY_ROLL_NO, LOG_CORE_STATE)
    print("\n--- Running again with logs OFF for performance check ---")
    run_chacha20_assignment(MY_ROLL_NO, log_switch=False)