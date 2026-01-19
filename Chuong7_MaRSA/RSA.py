#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chương 7: Hệ mật khóa bất đối xứng
7.1: So sánh symmetric vs asymmetric
7.2: Phân biệt public key, private key
7.3: Trapdoor function
7.4: RSA, ElGamal, Knapsack, Rabin
"""

def extended_gcd(a, b):
    """Extended GCD"""
    if b == 0:
        return a, 1, 0
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return g, x, y

def mod_inverse(a, m):
    """Tìm modular inverse"""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return -1
    return x % m

def is_prime_simple(n, k=10):
    """Simple prime check"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

# ============== RSA ==============

class RSA:
    """RSA Cryptosystem"""
    
    def __init__(self, p, q, e=None):
        """
        Khởi tạo RSA
        p, q: hai số nguyên tố
        e: public exponent (mặc định = 17 hoặc 65537)
        """
        self.p = p
        self.q = q
        self.n = p * q
        self.phi_n = (p - 1) * (q - 1)
        
        # Chọn e
        if e is None:
            e = 17
        self.e = e
        
        # Tính d
        self.d = mod_inverse(e, self.phi_n)
        
        print(f"   RSA Key Generated:")
        print(f"   p={p}, q={q}, n={self.n}, phi(n)={self.phi_n}")
        print(f"   Public key: (e={self.e}, n={self.n})")
        print(f"   Private key: (d={self.d}, n={self.n})")
    
    def encrypt(self, M):
        """Mã hóa: C = M^e mod n"""
        return pow(M, self.e, self.n)
    
    def decrypt(self, C):
        """Giải mã: M = C^d mod n"""
        return pow(C, self.d, self.n)
    
    def sign(self, M):
        """Ký: S = M^d mod n"""
        return pow(M, self.d, self.n)
    
    def verify(self, M, S):
        """Xác minh: M = S^e mod n"""
        return pow(S, self.e, self.n) == M

# ============== ElGamal ==============

class ElGamal:
    """ElGamal Cryptosystem"""
    
    def __init__(self, p, g, x=None):
        """
        Khởi tạo ElGamal
        p: số nguyên tố (large prime)
        g: generator
        x: private key (random)
        """
        self.p = p
        self.g = g
        self.x = x if x else 7  # Private key
        self.y = pow(g, self.x, p)  # Public key
        
        print(f"   ElGamal Key Generated:")
        print(f"   p={p}, g={g}")
        print(f"   Public key: y=g^x mod p = {self.y}")
        print(f"   Private key: x = {self.x}")
    
    def encrypt(self, M, k=None):
        """
        Mã hóa: (C1, C2) = (g^k mod p, M*y^k mod p)
        k: random ephemeral key
        """
        k = k if k else 5
        C1 = pow(self.g, k, self.p)
        C2 = (M * pow(self.y, k, self.p)) % self.p
        return C1, C2
    
    def decrypt(self, C1, C2):
        """Giải mã: M = C2 * (C1^x)^(-1) mod p"""
        s = pow(C1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        M = (C2 * s_inv) % self.p
        return M

# ============== KNAPSACK ==============

class Knapsack:
    """Knapsack Cryptosystem (simplified)"""
    
    def __init__(self, superincreasing_seq, m, w):
        """
        Khởi tạo Knapsack
        superincreasing_seq: dãy siêu tăng (private key)
        m: modulus
        w: multiplier (gcd(w,m)=1)
        """
        self.private_key = superincreasing_seq
        self.m = m
        self.w = w
        
        # Public key: a_i = w * b_i mod m
        self.public_key = [(w * b) % m for b in superincreasing_seq]
        
        print(f"   Knapsack Key Generated:")
        print(f"   Private key: {self.private_key}")
        print(f"   Public key: {self.public_key}")
    
    def encrypt(self, plaintext):
        """Mã hóa: C = sum(plaintext_i * public_key_i)"""
        ciphertext = sum(bit * key for bit, key in zip(plaintext, self.public_key))
        return ciphertext % self.m
    
    def decrypt(self, ciphertext):
        """Giải mã (cần private key)"""
        # Tìm w_inv sao cho w * w_inv ≡ 1 (mod m)
        w_inv = mod_inverse(self.w, self.m)
        decrypted_val = (ciphertext * w_inv) % self.m
        
        # Giải super-increasing knapsack
        plaintext = []
        for item in reversed(self.private_key):
            if decrypted_val >= item:
                plaintext.append(1)
                decrypted_val -= item
            else:
                plaintext.append(0)
        
        return list(reversed(plaintext))

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("CHƯƠNG 7: HỆ MẬT KHÓA BẤT ĐỐI XỨNG")
    print("=" * 70)
    
    # 1. So sánh
    print("\n1. SO SÁNH SYMMETRIC VS ASYMMETRIC")
    print("-" * 70)
    print("""
    Symmetric (AES, DES):
    - Dùng cùng một khóa để mã hóa và giải mã
    - Khóa phải được chia sẻ trước
    - Tốc độ: NHANH (1000x so với asymmetric)
    - Vấn đề: Key distribution
    
    Asymmetric (RSA, ElGamal):
    - Có public key (công khai) và private key (bí mật)
    - Không cần chia sẻ khóa trước
    - Tốc độ: CHẬM
    - Ứng dụng: Digital signature, key exchange, etc.
    """)
    
    # 2. RSA
    print("\n2. RSA (Rivest-Shamir-Adleman)")
    print("-" * 70)
    
    rsa = RSA(p=61, q=53, e=17)
    plaintext = 65
    
    print(f"\n   Encrypt:")
    print(f"   Plaintext: {plaintext}")
    ciphertext = rsa.encrypt(plaintext)
    print(f"   Ciphertext: {ciphertext}")
    
    print(f"\n   Decrypt:")
    decrypted = rsa.decrypt(ciphertext)
    print(f"   Decrypted: {decrypted}")
    
    # Kiểm chứng
    if decrypted == plaintext:
        print(f"   ✓ KIỂM CHỨNG RSA: Plaintext = Decrypted ✓")
    else:
        print(f"   ✗ LỖI: Plaintext ≠ Decrypted")
    
    # Digital Signature
    print(f"\n   Digital Signature:")
    message = 123
    signature = rsa.sign(message)
    print(f"   Message: {message}")
    print(f"   Signature: {signature}")
    verified = rsa.verify(message, signature)
    print(f"   Verified: {verified}")
    if verified:
        print(f"   ✓ KIỂM CHỨNG RSA SIGNATURE: Valid ✓")
    else:
        print(f"   ✗ LỖI: Signature invalid")
    
    # TEST: Sai signature
    print(f"\n   Test wrong signature:")
    wrong_sig = signature + 1
    verified_wrong = rsa.verify(message, wrong_sig)
    print(f"   Wrong signature: {wrong_sig}")
    print(f"   Verified (expected False): {verified_wrong}")
    if not verified_wrong:
        print(f"   ✓ Security check: Detected invalid signature ✓")
    
    # 3. ElGamal
    print("\n3. ELGAMAL")
    print("-" * 70)
    
    elgamal = ElGamal(p=23, g=5, x=6)
    plaintext_eg = 12
    
    print(f"\n   Encrypt:")
    print(f"   Plaintext: {plaintext_eg}")
    C1, C2 = elgamal.encrypt(plaintext_eg, k=3)
    print(f"   Ciphertext: ({C1}, {C2})")
    
    print(f"\n   Decrypt:")
    decrypted_eg = elgamal.decrypt(C1, C2)
    print(f"   Decrypted: {decrypted_eg}")
    
    # Kiểm chứng
    if decrypted_eg == plaintext_eg:
        print(f"   ✓ KIỂM CHỨNG ELGAMAL: Plaintext = Decrypted ✓")
    else:
        print(f"   ✗ LỖI: Plaintext ≠ Decrypted (Expected)")
    
    # 4. Knapsack
    print("\n4. KNAPSACK CRYPTOSYSTEM")
    print("-" * 70)
    
    super_inc = [2, 5, 11, 23, 46]
    m = 103
    w = 17
    knapsack = Knapsack(super_inc, m, w)
    
    plaintext_kn = [1, 0, 1, 0, 1]
    print(f"\n   Encrypt:")
    print(f"   Plaintext: {plaintext_kn}")
    ciphertext_kn = knapsack.encrypt(plaintext_kn)
    print(f"   Ciphertext: {ciphertext_kn}")
    
    print(f"\n   Decrypt:")
    decrypted_kn = knapsack.decrypt(ciphertext_kn)
    print(f"   Decrypted: {decrypted_kn}")
    
    # Kiểm chứng
    if decrypted_kn == plaintext_kn:
        print(f"   ✓ KIỂM CHỨNG KNAPSACK: Plaintext = Decrypted ✓")
    else:
        print(f"   ✗ LỖI: Plaintext ≠ Decrypted")
    
    # 4.5 ADDITIONAL TEST CASES
    print("\n4.5 ADDITIONAL TEST CASES")
    print("-" * 70)
    
    # RSA test cases
    print(f"\n   RSA Additional Tests:")
    test_messages = [1, 10, 100]
    for test_msg in test_messages:
        if test_msg < rsa.n:
            ct = rsa.encrypt(test_msg)
            dt = rsa.decrypt(ct)
            status = "✓" if test_msg == dt else "✗"
            print(f"   M={test_msg}: E={ct}, D={dt} {status}")
    
    # ElGamal test
    print(f"\n   ElGamal Additional Test:")
    plaintext_eg_2 = 15
    C1_2, C2_2 = elgamal.encrypt(plaintext_eg_2, k=5)
    decrypted_eg_2 = elgamal.decrypt(C1_2, C2_2)
    status_eg = "✓" if plaintext_eg_2 == decrypted_eg_2 else "✗"
    print(f"   M={plaintext_eg_2}: (C1={C1_2}, C2={C2_2}) → D={decrypted_eg_2} {status_eg}")
    
    # Knapsack test
    print(f"\n   Knapsack Additional Test:")
    plaintext_kn_2 = [0, 1, 1, 0, 1]
    ciphertext_kn_2 = knapsack.encrypt(plaintext_kn_2)
    decrypted_kn_2 = knapsack.decrypt(ciphertext_kn_2)
    status_kn = "✓" if plaintext_kn_2 == decrypted_kn_2 else "✗"
    print(f"   M={plaintext_kn_2}: C={ciphertext_kn_2} → D={decrypted_kn_2} {status_kn}")
    
    # 6. Trapdoor function
    print("\n6. TRAPDOOR FUNCTION")
    print("-" * 70)
    print("""
    Định nghĩa:
    - f(x) dễ tính khi biết x
    - f^(-1)(y) khó tính từ y
    - f^(-1)(y) dễ tính khi biết "trapdoor information"
    
    RSA Trapdoor:
    - Forward: C = M^e mod n (dễ - dùng fast exponentiation)
    - Backward (khó): M = C^d mod n (cần biết d = private key)
    - Trapdoor: Biết p, q → có thể tính d từ e
    
    ElGamal Trapdoor:
    - Forward: (C1, C2) = (g^k, M*y^k) (dễ)
    - Backward (khó): M = C2 * (C1^x)^(-1) (cần biết x)
    - Trapdoor: Biết x → có thể giải mã
    """)
    
    # 7. Bảo mật
    print("\n7. PHÂN TÍCH BẢO MẬT")
    print("-" * 70)
    print("""
    RSA:
    - Dựa vào độ khó của factoring
    - Hiện tại: 2048-bit RSA an toàn
    - 4096-bit: rất an toàn
    - Tấn công: Brute force (không khả thi), Side channel attacks
    
    ElGamal:
    - Dựa vào Discrete Log Problem
    - Cần p là prime lớn, generator g
    - Có thể có overhead lớn (ciphertext dài hơn plaintext 2x)
    
    Knapsack:
    - Đã bị phá vỡ (Shamir, Zippel)
    - KHÔNG dùng trong thực tế nữa
    - Chỉ dùng cho học tập
    """)
    
    print("\n" + "=" * 70)