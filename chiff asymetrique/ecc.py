import random

def mod_inverse(a, m):
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x

class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        
    def is_on_curve(self, point):
        if point is None:
            return True # Point at infinity
        x, y = point
        return (y**2 - (x**3 + self.a * x + self.b)) % self.p == 0
        
    def add(self, p1, p2):
        if not self.is_on_curve(p1) or not self.is_on_curve(p2):
            raise ValueError("Points are not on the curve")
            
        if p1 is None:
            return p2
        if p2 is None:
            return p1
            
        x1, y1 = p1
        x2, y2 = p2
        
        if x1 == x2 and y1 != y2:
            return None # Point at infinity
            
        if x1 == x2:
            # point doubling
            d = mod_inverse(2 * y1, self.p)
            if d == 0: # Inverse doesn't exist
                return None
            m = ((3 * x1**2 + self.a) * d) % self.p
        else:
            d = mod_inverse((x2 - x1) % self.p, self.p)
            if d == 0:
                return None
            m = ((y2 - y1) * d) % self.p
            
        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        
        return (x3, y3)
        
    def scalar_mult(self, k, point):
        result = None
        addend = point
        
        # Double and add algorithm
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
            
        return result

def get_base_point_and_curve():
    # Curve: y^2 = x^3 + 2x + 2 over F_17
    # This is a very small prime curve for educational demonstration
    p = 17
    a = 2
    b = 2
    curve = EllipticCurve(a, b, p)
    # Generator point
    G = (5, 1) # On this curve 5^3 + 2*5 + 2 = 125 + 10 + 2 = 137 = 1 (mod 17) -> y^2 = 1
    return curve, G

def menu() -> None:
    print("=" * 50)
    print("      Elliptic Curve Cryptography (ECDH Demo)")
    print("=" * 50)

    curve, G = get_base_point_and_curve()
    print(f"Using Curve y^2 = x^3 + {curve.a}x + {curve.b} mod {curve.p}")
    print(f"Base generator point G = {G}\n")

    while True:
        print("Options:")
        print("  1. Perform ECDH Key Exchange")
        print("  2. Demonstrate Scalar Multiplication")
        print("  3. Exit")
        choice = input("\nChoose [1-3]: ").strip()

        if choice == '3':
            break

        if choice == '1':
            try:
                print("\n--- Alice ---")
                alice_private = random.randint(1, curve.p - 1)
                alice_public = curve.scalar_mult(alice_private, G)
                print(f"Alice's Private Key = {alice_private}")
                print(f"Alice's Public Key = {alice_public}")
                
                print("\n--- Bob ---")
                bob_private = random.randint(1, curve.p - 1)
                bob_public = curve.scalar_mult(bob_private, G)
                print(f"Bob's Private Key = {bob_private}")
                print(f"Bob's Public Key = {bob_public}")
                
                print("\n--- Exchange & Shared Secret ---")
                alice_shared = curve.scalar_mult(alice_private, bob_public)
                bob_shared = curve.scalar_mult(bob_private, alice_public)
                
                print(f"Alice computes shared secret: {alice_shared}")
                print(f"Bob computes shared secret: {bob_shared}")
                
                if alice_shared == bob_shared:
                    print("Success! Both parties have identical shared secrets computed via ECC.")
                else:
                    print("Error: Shared secrets do not match.")
                    
            except Exception as e:
                print(f"Error: {e}")

        elif choice == '2':
            try:
                k = int(input(f"Enter scalar multiplier k (integer > 0): "))
                P = curve.scalar_mult(k, G)
                print(f"{k} * {G} = {P}")
            except Exception as e:
                print(f"Error: {e}")
                
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    menu()
