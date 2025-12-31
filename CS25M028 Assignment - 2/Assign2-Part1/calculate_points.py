import sys

# --- Elliptic Curve Parameters for secp256k1 ---

x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (x,y)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007

print("--- Curve: secp256k1 ---")
print(f"Equation: y^2 = x^3 + {a}x + {b}")
print(f"Field Prime (p): {p}")
print("-" * 40)


def modular_inverse(n, prime):
    """Calculates the modular multiplicative inverse of n modulo prime."""
    return pow(n, -1, prime)

def add_points(p1, p2):
    """Performs point addition on an elliptic curve P1 + P2."""
    if p1 is None: return p2
    if p2 is None: return p1

    x1, y1 = p1
    x2, y2 = p2

    print(f"Performing Point Addition on ({x1}, {y1}) and ({x2}, {y2})\n")
    # Slope (s) = (y2 - y1) / (x2 - x1) mod p
    numerator = (y2 - y1) % p
    denominator = (x2 - x1) % p

    if denominator == 0: return None

    inv_denominator = modular_inverse(denominator, p)
    s = (numerator * inv_denominator) % p
    print(f"  Slope (s) = ({y2} - {y1}) * ({x2} - {x1})^-1 mod p = {s}\n")
    # New coordinates
    x3 = (s**2 - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    print(f"  New Point (x, y) = ({x3}, {y3})\n")
    return (x3, y3)

# --- Main execution ---
# Get the base point G (1G)
base_point_G = G
print(f"Base Point G (1G) = {base_point_G}\n")

points = [base_point_G]
current_point = base_point_G

numerator = (3 * x**2 + a) % p
denominator = (2 * y) % p
    
inv_denominator = modular_inverse(denominator, p)
s = (numerator * inv_denominator) % p
print("\n")
print(f"Calculating 2G = G + G")
print(f"Performing Point Addition on ({x}, {y}) and ({x}, {y}) \n")
print(f"  Slope (s) = (3*{x}^2 + {a}) * (2*{y})^-1 mod p = {s} \n")

# New coordinates
x3 = (s**2 - 2 * x) % p
y3 = (s * (x - x3) - y) % p

print(f"  New Point (x, y) = ({x3}, {y3}) \n")
current_point =(x3, y3)
points.append(current_point)

print(f"Result for 2G = {current_point}")

# Calculate points from 3G to 10G by adding G each time
for i in range(3, 11):
    print("\n \n")
    print(f"Calculating {i}G = {i-1}G + G")
    current_point = add_points(current_point, base_point_G)
    points.append(current_point)
    print(f"Result for {i}G = {current_point}")

