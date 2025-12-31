import configparser
import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

CONFIG_FILE = 'secrets.ini'

def load_keys():
    """
    Loads the master keys from the secrets.ini file.
    This is our "simulated KMS".
    """
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"CRITICAL: Secrets file not found at {CONFIG_FILE}")
        
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    try:
        mek = bytes.fromhex(config['keys']['MASTER_ENCRYPTION_KEY'])
        aik = bytes.fromhex(config['keys']['APPLICATION_INTEGRITY_KEY'])
        
        if len(mek) != 32 or len(aik) != 32:
            raise ValueError("Keys must be 32 bytes (64 hex characters) long.")
            
        return mek, aik
    except KeyError as e:
        raise KeyError(f"CRITICAL: Key {e} not found in {CONFIG_FILE}")
    except ValueError as e:
        raise ValueError(f"CRITICAL: Key format error in {CONFIG_FILE}. {e}")

# --- ACL Encryption (Data) ---

def encrypt_data(master_key, plaintext_data):
    """
    Encrypts small data (like ACL permissions) using AES-GCM.
    Returns a hex-encoded string of "nonce:ciphertext:tag".
    """
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12) # 96-bit nonce
    
    ct_and_tag = aesgcm.encrypt(nonce, plaintext_data.encode('utf-8'), None)
    
    # Separate ciphertext and tag
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    
    # Return as a single hex string for easy DB storage
    return f"{nonce.hex()}:{ciphertext.hex()}:{tag.hex()}"

def decrypt_data(master_key, hex_data):
    """
    Decrypts the "nonce:ciphertext:tag" hex string from the database.
    """
    try:
        nonce_hex, ct_hex, tag_hex = hex_data.split(':')
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ct_hex)
        tag = bytes.fromhex(tag_hex)
        
        aesgcm = AESGCM(master_key)
        
        # Combine ciphertext and tag for decryption
        ct_and_tag = ciphertext + tag
        
        decrypted_bytes = aesgcm.decrypt(nonce, ct_and_tag, None)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"ACL Decryption FAILED: {e}")
        raise ValueError("Decryption failed. Data may be corrupt or tampered with.")

# --- File Encryption (Streams) ---

def encrypt_file(master_key, file_bytes):
    """
    Encrypts a file's content using a unique File Encryption Key (FEK).
    Implements envelope encryption.
    Returns (encrypted_content, fek_hex)
    """
    # 1. Generate a unique File Encryption Key (FEK) for this file
    fek = AESGCM.generate_key(bit_length=256)
    
    # 2. Encrypt the file content with the FEK
    aesgcm = AESGCM(fek)
    nonce = os.urandom(12)
    ct_and_tag = aesgcm.encrypt(nonce, file_bytes, None)
    encrypted_content = nonce + ct_and_tag # Prepend nonce to ciphertext
    
    # 3. Encrypt the FEK with the Master Key (MEK)
    # This is "envelope encryption"
    encrypted_fek = encrypt_data(master_key, fek.hex())
    
    # We return the encrypted content and the *encrypted* FEK (as hex)
    # The 'app.py' will store the encrypted_fek in the database
    return encrypted_content, encrypted_fek

def decrypt_file_stream(master_key, encrypted_fek_hex, encrypted_file_path):
    """
    A generator that decrypts a file on-the-fly for streaming.
    """
    try:
        # 1. Decrypt the File Encryption Key (FEK)
        fek_hex = decrypt_data(master_key, encrypted_fek_hex)
        fek = bytes.fromhex(fek_hex)
        
        # 2. Prepare the cipher with the decrypted FEK
        aesgcm = AESGCM(fek)
        
        with open(encrypted_file_path, 'rb') as f:
            # 3. Read the 12-byte nonce from the start of the file
            nonce = f.read(12)
            if len(nonce) != 12:
                raise ValueError("Encrypted file is corrupt (invalid nonce).")
            
            # 4. Read and decrypt the rest of the file in chunks
            # For AES-GCM, we must decrypt the *entire* ciphertext at once
            # In a real-world streaming app, we'd use AES-CTR or CBC.
            # For this project, we'll read the whole file.
            ct_and_tag = f.read()
            
            decrypted_bytes = aesgcm.decrypt(nonce, ct_and_tag, None)
            
            # This 'yield' makes it a generator, which stream_with_context expects
            yield decrypted_bytes
            
    except Exception as e:
        print(f"File decryption stream FAILED: {e}")
        # Yield an error message to the user
        yield f"Error: Could not decrypt file. {e}".encode('utf-8')

# --- Hashing & Integrity ---

def hash_data(data_bytes):
    """
    Generates a SHA-256 hash of data.
    """
    h = hashlib.sha256()
    h.update(data_bytes)
    return h.hexdigest()

def generate_hmac(integrity_key, message):
    """
    Generates an HMAC-SHA256 tag for a message.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    tag = hmac.new(integrity_key, message, hashlib.sha256)
    return tag.hexdigest()

def verify_hmac(integrity_key, expected_hmac_hex, message):
    """
    Verifies an HMAC tag. Returns True if valid, False otherwise.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
        
    # Generate the HMAC we *expect* to see
    calculated_hmac = hmac.new(integrity_key, message, hashlib.sha256)
    calculated_hmac_hex = calculated_hmac.hexdigest()
    
    # Compare the expected vs. calculated tag in a secure way
    return hmac.compare_digest(expected_hmac_hex, calculated_hmac_hex)

