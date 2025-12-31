import os
import sys
import hashlib

# --- PART A: FROM-SCRATCH ELLIPTIC CURVE CRYPTOGRAPHY IMPLEMENTATION ---

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
    if x1 == x2 and y1 != y2: return curve.infinity
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
        if k & 1: result = point_add(result, current_addend, curve)
        current_addend = point_add(current_addend, current_addend, curve)
        k >>= 1
    return result

# --- PART B: VERIFICATION SCRIPT LOGIC ---
# --- CONFIGURATION ---
LOG_FILE_TO_VERIFY = r"C:\Users\majji\Downloads\alpha_files_T15_q3\alpha_files\log_part1+2.txt"
SIGNATURE_FILE = r"C:\Users\majji\Downloads\signature.sig"
curve = SECP256r1

print("--- ECDSA Signature Verification ---")
print(f"Curve: secp256r1")
print("-" * 50)

# --- KEY SETUP (FIXED PUBLIC KEY) ---
# IMPORTANT: These values must be copied from the output of the signing script.
# The verifier only has the public key, not the private one.
public_key_x = 112863896899875822889456381670897237678352397846286905118479665794274073622681
public_key_y = 82961549504873275069612684407161012057628309892335449696174109844176769371600
public_key_point = (public_key_x, public_key_y)
print("Using fixed public key (Q):")
print(f"  Qx: {public_key_point[0]}")
print(f"  Qy: {public_key_point[1]}")
print("-" * 50)

# --- VERIFY THE SIGNATURE ---
print(f" Verifying signature for file: '{LOG_FILE_TO_VERIFY}'...")
try:
    with open(SIGNATURE_FILE, "rb") as f:
        sig_bytes = f.read()
    with open(LOG_FILE_TO_VERIFY, "rb") as f:
        file_to_verify_data = f.read()

    r_v = int.from_bytes(sig_bytes[:32], 'big')
    s_v = int.from_bytes(sig_bytes[32:], 'big')
    print(f"  Read signature (r): {r_v}")
    print(f"  Read signature (s): {s_v}")
    
    verifier_hash = hashlib.sha256(file_to_verify_data).digest()
    z_v = int.from_bytes(verifier_hash, 'big')
    print(f"  Recalculated Hash (z): {z_v}")

    # ECDSA Verification Algorithm
    w = modular_inverse(s_v, curve.n)
    u1 = (z_v * w) % curve.n
    u2 = (r_v * w) % curve.n
    print(f"  w = s^-1 mod n = {w}")
    print(f"  u1 = z*w mod n = {u1}")
    print(f"  u2 = r*w mod n = {u2}")

    P_prime_u1 = scalar_multiply(u1, curve.G, curve)
    P_prime_u2 = scalar_multiply(u2, public_key_point, curve)
    P_prime = point_add(P_prime_u1, P_prime_u2, curve)

    print(f"  Verification Point P' = ({P_prime[0]}, {P_prime[1]})")

    if P_prime is not None and P_prime[0] % curve.n == r_v:
        print("\n RESULT: SIGNATURE IS VALID.")
        print(" The file's integrity and authenticity are confirmed.")
    else:
        print("\n RESULT: SIGNATURE IS INVALID.")
        print(" The file may have been altered, or the key is incorrect.")

except FileNotFoundError:
    print(f" ERROR: Could not find '{LOG_FILE_TO_VERIFY}' or '{SIGNATURE_FILE}'.")
    sys.exit()
except Exception as e:
    print(f" An error occurred during verification: {e}")
