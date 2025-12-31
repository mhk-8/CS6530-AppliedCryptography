import os
import random
import sys
import hashlib

# PART B: FROM-SCRATCH ELLIPTIC CURVE CRYPTOGRAPHY IMPLEMENTATION

class Curve:
    def __init__(self, p, a, b, Gx, Gy, n, h):
        self.p = p
        self.a = a
        self.b = b
        self.Gx = Gx
        self.Gy = Gy
        self.n = n
        self.h = h
        self.G = (Gx, Gy)
        self.infinity = None # Represents the point at infinity

# secp256r1 parameters
p_nist = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a_nist = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b_nist = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx_nist = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy_nist = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
n_nist = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
h_nist = 1

SECP256r1 = Curve(p_nist, a_nist, b_nist, Gx_nist, Gy_nist, n_nist, h_nist)

def modular_inverse(a, n):
    """Calculates the modular inverse of a modulo n."""
    return pow(a, -1, n)

def point_add(P, Q, curve):
    """Adds two points on the elliptic curve."""
    if P == curve.infinity: return Q
    if Q == curve.infinity: return P
    
    x1, y1 = P
    x2, y2 = Q
    
    if x1 == x2 and y1 != y2:
        return curve.infinity
    
    if P == Q: # Point doubling
        lam = (3 * x1 * x1 + curve.a) * modular_inverse(2 * y1, curve.p)
    else: # Point addition
        lam = (y2 - y1) * modular_inverse(x2 - x1, curve.p)
        
    x3 = (lam * lam - x1 - x2) % curve.p
    y3 = (lam * (x1 - x3) - y1) % curve.p
    
    return (x3, y3)

def scalar_multiply(k, P, curve):
    """Performs scalar multiplication k * P using the double-and-add algorithm."""
    result = curve.infinity
    current_addend = P
    
    while k > 0:
        if k & 1: # If bit is 1, add
            result = point_add(result, current_addend, curve)
        current_addend = point_add(current_addend, current_addend, curve) # Double
        k >>= 1
        
    return result

# PART C: MAIN SCRIPT LOGIC 

# CONFIGURATION 
LOG_FILE_TO_SIGN = r"C:\Users\majji\OneDrive\Desktop\mtech_learninng\Applied_cryptography\CS25M028_Assignment_2\Assign2-Part3\combined_log.txt"
SIGNATURE_FILE = "signature.sig"
curve = SECP256r1

print(" ECDSA Signature with hashlib and From-Scratch ECC ")
print(f"Curve: secp256r1")

# --- KEY GENERATION ---
print("\n Generating new ECDSA key pair...")
private_key_int = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
public_key_point = scalar_multiply(private_key_int, curve.G, curve)

print(f"  Private Key (d): {private_key_int}")
print(f"  Public Key (Qx): {public_key_point[0]}")
print(f"  Public Key (Qy): {public_key_point[1]}")
print("\n")


# --- HASH AND SIGN THE FILE ---
print(f" Signing the file: '{LOG_FILE_TO_SIGN}'...")
try:
    with open(LOG_FILE_TO_SIGN, "rb") as f:
        file_data = f.read()

    # Use hashlib for SHA-256
    file_hash = hashlib.sha256(file_data).digest()
    z = int.from_bytes(file_hash, 'big')
    print(f"  File SHA-256 Hash (hex): {file_hash.hex()}")
    print(f"  Hash as Integer (z): {z}")

    # ECDSA Signing Algorithm
    r, s = 0, 0
    rng = random.SystemRandom()
    while r == 0 or s == 0:
        k = rng.randrange(1, curve.n)
        P = scalar_multiply(k, curve.G, curve)
        r = P[0] % curve.n
        k_inv = modular_inverse(k, curve.n)
        s = (k_inv * (z + r * private_key_int)) % curve.n

    print(f"  Ephemeral Key (k): {k}")
    print(f"  Signature part (r): {r}")
    print(f"  Signature part (s): {s}")

    # Save signature as simple concatenated bytes
    signature_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    with open(SIGNATURE_FILE, "wb") as f:
        f.write(signature_bytes)

    print(f"\n  SUCCESS: Signature (r,s) calculated and saved to '{SIGNATURE_FILE}'")

except FileNotFoundError:
    print(f"  ERROR: The file '{LOG_FILE_TO_SIGN}' was not found.")
    sys.exit()
print("\n")


