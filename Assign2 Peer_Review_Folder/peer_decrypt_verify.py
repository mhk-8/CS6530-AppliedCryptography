import os
import zipfile
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Import the ChaCha20 implementation
try:
    from CS25M028_ChaCha20 import chacha20_crypt
except ImportError:
    print("ERROR: Make sure 'CS25M028_ChaCha20.py' is in the same directory.")
    exit()

# --- 1. CONFIGURATION (PEER'S SIDE) ---
CURVE = ec.SECP256R1()
ENCRYPTED_FILE = "Assignment2_Encrypted.bin"
DECRYPTED_ZIP = "Assignment2_Decrypted.zip"
SIGNATURE_FILE = "signature.sig" # From Alice

# --- This is the critical information the Peer needs from Alice ---
# In a real application, Alice's public key would be sent as a file (e.g., PEM format)
# For this simulation, we will regenerate Alice's keys and just use the public part.
# IMPORTANT: To make this script runnable, we simulate Alice's key generation here.
# The peer would receive alice_public_key, not generate it.
alice_simulated_private_key = ec.generate_private_key(CURVE)
ALICE_PUBLIC_KEY = alice_simulated_private_key.public_key() 
# The nonce must be the SAME one Alice used for encryption.
NONCE = b'CS6530Nonce!' # 12 bytes

print("--- Peer Review: Decryption and Signature Verification ---")
print("-" * 50)

# --- 2. GENERATE PEER'S (BOB'S) KEYS ---
print("[STEP 1] Peer (Bob) generates their own key pair...")
bob_private_key = ec.generate_private_key(CURVE)
bob_public_key = bob_private_key.public_key()
print("  Bob's keys have been generated.")
print("-" * 50)

# --- 3. DERIVE SHARED SECRET & DECRYPT ---
print("[STEP 2] Decrypting the received file...")
try:
    # Bob computes the shared secret using HIS private key and ALICE'S public key
    bob_shared_key = bob_private_key.exchange(ec.ECDH(), ALICE_PUBLIC_KEY)

    # Use the same KDF (SHA-256) to derive the symmetric key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bob_shared_key)
    bob_derived_key = digest.finalize()
    print(f"  Shared key derived successfully: {bob_derived_key[:8].hex()}...")

    # Read the encrypted file
    with open(ENCRYPTED_FILE, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt the data using ChaCha20
    decrypted_data = chacha20_crypt(key=bob_derived_key, nonce=NONCE, plaintext=encrypted_data)

    # Save the decrypted zip file
    with open(DECRYPTED_ZIP, 'wb') as f:
        f.write(decrypted_data)
    print(f"  SUCCESS: File decrypted and saved as '{DECRYPTED_ZIP}'")

except FileNotFoundError:
    print(f"  ERROR: Could not find '{ENCRYPTED_FILE}'. Make sure it's in the same folder.")
    exit()
except Exception as e:
    print(f"  An error occurred during decryption: {e}")
    exit()
print("-" * 50)


# --- 4. UNZIP THE ARCHIVE & FIND LOG FILE ---
print("[STEP 3] Unzipping the archive to find the log file for signature verification...")
LOG_FILE_TO_VERIFY = 'Assign2-Part3/combined_log.txt' # Path inside the zip
try:
    with zipfile.ZipFile(DECRYPTED_ZIP, 'r') as zip_ref:
        zip_ref.extractall(".") # Extract to current directory
    print(f"  SUCCESS: Archive '{DECRYPTED_ZIP}' extracted.")
    
    if not os.path.exists(LOG_FILE_TO_VERIFY):
        print(f"  ERROR: Expected log file '{LOG_FILE_TO_VERIFY}' not found in the zip archive.")
        exit()

except zipfile.BadZipFile:
    print("  ERROR: The decrypted file is not a valid zip archive. The key or nonce may be incorrect.")
    exit()
print("-" * 50)

# --- 5. VERIFY THE DIGITAL SIGNATURE ---
print(f"[STEP 4] Verifying the signature of '{LOG_FILE_TO_VERIFY}'...")
try:
    # Read the signature from the file provided by Alice
    with open(SIGNATURE_FILE, "rb") as f:
        signature_to_verify = f.read()
        
    # Read the log file that was just extracted
    with open(LOG_FILE_TO_VERIFY, "rb") as f:
        log_file_data = f.read()

    # Calculate the SHA-256 hash of the extracted log file
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(log_file_data)
    log_file_hash = hasher.finalize()
    print(f"  Recalculated SHA-256 Hash of log file: {log_file_hash.hex()}")
    
    # Use Alice's public key to verify the signature against the hash
    # Note: For ECDSA, we need to use a different curve object for verification.
    verify_curve = ec.SECP256R1() # P-256 curve for ECDSA
    ALICE_PUBLIC_KEY_FOR_ECDSA = ec.generate_private_key(verify_curve).public_key() # Simulate again for the right type
    
    ALICE_PUBLIC_KEY.verify(
        signature_to_verify,
        log_file_hash,
        ec.ECDSA(hashes.SHA256())
    )
    
    print("\n  ✅ RESULT: SIGNATURE IS VALID.")
    print("     This confirms the log file is authentic and has not been altered.")

except InvalidSignature:
    print("\n  ❌ RESULT: SIGNATURE IS INVALID.")
    print("     The log file may have been tampered with or was not signed with the correct key.")
except FileNotFoundError:
    print(f"  ERROR: Could not find '{LOG_FILE_TO_VERIFY}' or '{SIGNATURE_FILE}' for verification.")
print("-" * 50)