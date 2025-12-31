import sys

# --- Elliptic Curve Parameters for secp256k1 ---
x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (x,y)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007

def modular_inverse(n, prime):
    """Calculates the modular multiplicative inverse of n modulo prime."""
    return pow(n, -1, prime)

def add_points(p1, p2):
    """Performing point addition on an elliptic curve P1 + P2."""
    if p1 is None: return p2
    if p2 is None: return p1

    x1, y1 = p1
    x2, y2 = p2

    # Point Doubling
    if p1 == p2:
        numerator = (3 * x1**2 + a) % p
        denominator = (2 * y1) % p
        if denominator == 0: return None
        inv_denominator = modular_inverse(denominator, p)
        s = (numerator * inv_denominator) % p
        x3 = (s**2 - 2 * x1) % p
        y3 = (s * (x1 - x3) - y1) % p
        #print(f"  x = {x3}")
        #print(f"  y = {y3}")
        return (x3, y3)
    # Point Addition
    else:
        numerator = (y2 - y1) % p
        denominator = (x2 - x1) % p
        if denominator == 0: return None
        inv_denominator = modular_inverse(denominator, p)
        s = (numerator * inv_denominator) % p
        x3 = (s**2 - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        #print(f"  x = {x3}")
        #print(f"  y = {y3}")
        return (x3, y3)

def double_and_add(k, point):
    
    #Performs scalar multiplication k * P using the Double and Add algorithm.
    
    binary_k = bin(k)[2:]
    
    print(f"Calculating {k}P using binary: {binary_k}")
    
    result = None  # This represents the point at infinity
    current_addend = point  # This starts at P and becomes 2P, 4P, 8P, etc.
    
    # Iterate through the binary string from right to left
    for bit in reversed(binary_k):
        if bit == '1':
            print(f"Bit is 1. Adding current point...")
            result = add_points(result, current_addend)
        
        print("Doubling current point for next bit...")
        current_addend = add_points(current_addend, current_addend) # Double
        
    return result

# --- Main execution ---
base_point_G = G
scalars = [1201, 3966, 4207]

final_points = {}

for k in scalars:
    print("\n\n")
    print(f"STARTING CALCULATION FOR k = {k}")
    print("\n")
    # The add_points function logs the detailed steps of each operation
    final_point = double_and_add(k, base_point_G)
    final_points[k] = final_point
    
    print("\n" )
    print(f"FINAL RESULT FOR {k}P:")
    if final_point:
        print(f"  x = {final_point[0]}")
        print(f"  y = {final_point[1]}")
    else:
        print("  Point at Infinity")
    