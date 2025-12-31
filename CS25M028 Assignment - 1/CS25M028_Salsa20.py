import struct
import time
import os
import binascii

# Creating a Global logger list to store log messages
LOG_MESSAGES = []

def log(message):
    """Appends a message to the global log list."""
    LOG_MESSAGES.append(message)

def rotl(x, n):
    """Performs a 32-bit left rotation."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def quarter_round(a, b, c, d, log_enabled=False):
    """ Performs a Salsa20 quarter round on four 32-bit integers. """
    b ^= rotl(d + a, 7)
    c ^= rotl(a + b, 9)
    d ^= rotl(b + c, 13)
    a ^= rotl(c + d, 18)
    if log_enabled:
        log(f"    QR Output: a={a:08x}, b={b:08x}, c={c:08x}, d={d:08x}")
    return a, b, c, d

def format_state(state):
    """Formats the 16-element state matrix for logging."""
    return "\n".join([f"    {state[i]:08x} {state[i+1]:08x} {state[i+2]:08x} {state[i+3]:08x}" for i in range(0, 16, 4)])

def salsa20_block(key, nonce, counter, log_enabled=False):
    """ Generates one 64-byte (512-bit) keystream block from a key, nonce, and counter.
    This is the core function of the cipher. """
    # 1. Initial State Setup
    # Constants "expand 32-byte k"
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    # Unpack key, nonce, and counter into 32-bit little-endian integers
    k = list(struct.unpack('<8L', key))
    n = list(struct.unpack('<2L', nonce))
    c = list(struct.unpack('<2L', counter.to_bytes(8, 'little')))

    # Initial 4x4 state matrix
    # [c0, k0, k1, k2]
    # [k3, c1, n0, n1]
    # [c , c , c2, k4]
    # [k5, k6, k7, c3]
    initial_state = [
        constants[0], k[0], k[1], k[2],
        k[3], constants[1], n[0], n[1],
        c[0], c[1], constants[2], k[4],
        k[5], k[6], k[7], constants[3]
    ]
    
    state = list(initial_state)
    if log_enabled:
        log("\n--- Salsa20 Block Generation ---")
        log(f"Initial State (Key, Nonce, Counter):")
        log(format_state(state))

    # 2. 20 Rounds (10 double rounds) of computation
    for i in range(10): # 10 double rounds
        if log_enabled:
            log(f"\n-- Double Round {i+1}/10 --")
            
        # Column Round
        if log_enabled: log("  Column Round:")
        state[0], state[4], state[8], state[12] = quarter_round(state[0], state[4], state[8], state[12], log_enabled)
        state[5], state[9], state[13], state[1] = quarter_round(state[5], state[9], state[13], state[1], log_enabled)
        state[10], state[14], state[2], state[6] = quarter_round(state[10], state[14], state[2], state[6], log_enabled)
        state[15], state[3], state[7], state[11] = quarter_round(state[15], state[3], state[7], state[11], log_enabled)
        if log_enabled:
            log("  State after Column Round:")
            log(format_state(state))

        # Row Round
        if log_enabled: log("  Row Round:")
        state[0], state[1], state[2], state[3] = quarter_round(state[0], state[1], state[2], state[3], log_enabled)
        state[5], state[6], state[7], state[4] = quarter_round(state[5], state[6], state[7], state[4], log_enabled)
        state[10], state[11], state[8], state[9] = quarter_round(state[10], state[11], state[8], state[9], log_enabled)
        state[15], state[12], state[13], state[14] = quarter_round(state[15], state[12], state[13], state[14], log_enabled)
        if log_enabled:
            log("  State after Row Round:")
            log(format_state(state))

    # 3. Final Addition
    final_state = [(initial_state[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    if log_enabled:
        log("\nFinal State (after addition):")
        log(format_state(final_state))

    # 4. Serialize the state to a 64-byte block (little-endian)
    keystream_block = b''.join([struct.pack('<L', x) for x in final_state])
    if log_enabled:
        log(f"\nGenerated 64-byte Keystream Block: { binascii.hexlify(keystream_block).decode('ascii')}")
    
    return keystream_block

def salsa20_crypt(key, nonce, plaintext, initial_counter=0):
    """ Encrypts or decrypts a plaintext using Salsa20.
    Encryption and decryption are the same operation. """
    ciphertext = bytearray()
    counter = initial_counter
    
    for i in range(0, len(plaintext), 64):
        keystream_block = salsa20_block(key, nonce, counter)
        block = plaintext[i:i+64]
        
        # XOR plaintext block with keystream block
        encrypted_block = bytes([block[j] ^ keystream_block[j] for j in range(len(block))])
        ciphertext.extend(encrypted_block)
        counter += 1
        
    return bytes(ciphertext)

def run_salsa20_assignment(roll_no, log_switch):
    """ Main function to run all parts of the Salsa20 assignment."""
    global LOG_MESSAGES
    LOG_MESSAGES = [] # Clear logs for this run
    
    print("--- Running Salsa20 Assignment ---")
    
    #  Part 1: Diffusion Analysis 
    print("Part 1: Performing diffusion analysis...")
    log(" CS6530 Applied Cryptography - Assignment 1 - Salsa20 Analysis ")
    log(f"Roll Number: {roll_no}\n")
    
    # Setup for diffusion test
    key = b'\x00' * 32
    nonce = b'\x00' * 8
    
    log("Analysis for Counter values 0 and 1 ")
    log("Key: all zeros, Nonce: all zeros")
    log(f"\n--- COUNTER 0 ---")
    salsa20_block(key, nonce, 0, log_enabled=log_switch)
    log(f"\n--- COUNTER 1 ---")
    salsa20_block(key, nonce, 1, log_enabled=log_switch)
    
    roll_no_val = int(''.join(filter(str.isdigit, roll_no))[-2:])
    log(f"\nAnalysis for Counter values {roll_no_val} and {roll_no_val + 1} ")
    log("Key: all zeros, Nonce: all zeros")
    log(f"\n--- COUNTER {roll_no_val} ---")
    salsa20_block(key, nonce, roll_no_val, log_enabled=log_switch)
    log(f"\n--- COUNTER {roll_no_val + 1} ---")
    salsa20_block(key, nonce, roll_no_val + 1, log_enabled=log_switch)
    
    part1_output_file = f"{roll_no}_CS6530_Assgn1_Part1_Salsa20.txt"
    with open(part1_output_file, 'w') as f:
        f.write("\n".join(LOG_MESSAGES))
    print(f"Part 1 analysis saved to {part1_output_file}")
    print(f"File size: {os.path.getsize(part1_output_file)} bytes ")

    #  Part 2: File Encryption/Decryption 
    print("\nPart 2: Performing file encryption and decryption...")
    
    # Use the Part 1 output file as plaintext
    plaintext_file = part1_output_file
    encrypted_file = f"{roll_no}_CS6530_Assgn1_Part1_Salsa20_Encrypted.bin"
    decrypted_file = f"{roll_no}_CS6530_Assgn1_Part1_Salsa20_decrypted.txt"
    
    # A fixed key and nonce for the file encryption part
    file_key = b'MySecretKeyForFileEncryption1234' # 32 bytes
    file_nonce = b'MyNonce1' # 8 bytes
    
    with open(plaintext_file, 'rb') as f:
        plaintext_data = f.read()

    # Encryption
    start_time = time.time()
    encrypted_data = salsa20_crypt(file_key, file_nonce, plaintext_data)
    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"Encryption completed in {encryption_time:.6f} seconds.")
    
    with open(encrypted_file, 'wb') as f:
        f.write(encrypted_data)
    print(f"Encrypted file saved to {encrypted_file}")
    print(f"File size: {os.path.getsize(encrypted_file)} bytes")

    # Decryption
    start_time = time.time()
    decrypted_data = salsa20_crypt(file_key, file_nonce, encrypted_data)
    end_time = time.time()
    decryption_time = end_time - start_time
    print(f"Decryption completed in {decryption_time:.6f} seconds. ")
    
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted_data)
    print(f"Decrypted file saved to {decrypted_file}")
    
    # Verification 
    if plaintext_data == decrypted_data:
        print("Verification successful: Original and decrypted files are identical.")
    else:
        print("Verification FAILED: Original and decrypted files differ.")

    #  Part 3: Performance Analysis 
    print("\nPart 3: Performing performance analysis...")
    # This test measures the cipher's raw speed by encrypting a large buffer
    # The log switch should be OFF for accurate performance measurement 
    
    if log_switch:
        print("WARNING: Log switch is ON. Performance measurement will be inaccurate.")
        
    perf_data = b'\x00' * (1024 * 1024) # 1 MB of data
    
    start_time = time.time()
    salsa20_crypt(key, nonce, perf_data)
    end_time = time.time()
    
    perf_time = end_time - start_time
    speed_mb_s = (len(perf_data) / (1024 * 1024)) / perf_time
    
    print(f"Salsa20 performance: Encrypted 1 MB in {perf_time:.6f} seconds.")
    print(f"Approximate speed: {speed_mb_s:.2f} MB/s")
    print("Compare this with the performance of the reference C implementation.")
    print("-" * 30 + "\n")

if __name__ == '__main__':
    MY_ROLL_NO = "CS25M028"
    LOG_CORE_STATE = True  # Switch to enable/disable detailed logs 
    
    # Run the assignment with detailed logs enabled
    run_salsa20_assignment(MY_ROLL_NO, LOG_CORE_STATE)

    # Run again with logs disabled for performance comparison observation 
    print("\n--- Running again with logs OFF for performance check ---")
    run_salsa20_assignment(MY_ROLL_NO, log_switch=False)