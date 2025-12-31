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
curve = SECP256r1
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
private_key = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
Public_Key_x: 43872280807156713839160376167191808430140484563252114113014272064716834774966
Public_Key_y: 54736908695619294235531183715189990111299271757105154178488727263331972686489
peer_public_x =hex(input("enter peer's public key x: "))
peer_public_y = hex(input("enter peer's public key y: "))

SharedSecret = scalar_multiply(int(private_key),(peer_public_x,peer_public_y),curve)

x_coor = SharedSecret[0].to_bytes(32,'big')
ChaCha_key = hashlib.sha256(x_coor).digest()
nonce = 0x000000000000000000000000
print("ChaCha_key: ",ChaCha_key.hex())