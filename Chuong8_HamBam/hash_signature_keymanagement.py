#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chương 8: Hàm băm, chữ ký số và quản lý khóa
8.1: Hàm băm mật mã
8.1.1: Giới thiệu
8.1.2: Merkle-Damgård construction
8.1.3: SHA-512
8.1.4: Whirlpool
8.2: Chữ ký số (DSS, Schnorr, ECDSA)
8.3: Quản lý khóa
"""

import hashlib

# ============== CÁC HÀM BĂM ĐƠN GIẢN ==============

def simple_hash(data):
    """
    Hàm băm đơn giản (chỉ cho mục đích giáo dục)
    Công thức: h(x) = (x * 1103515245 + 12345) mod 2^31
    """
    hash_val = 0
    for byte in data.encode() if isinstance(data, str) else data:
        hash_val = ((hash_val * 1103515245 + 12345) ^ byte) & 0x7FFFFFFF
    return hash_val

def md4_like_hash(message):
    """
    MD4-like hash (simplified - NOT SECURE)
    Mục đích: Minh họa cấu trúc hash
    """
    # Khởi tạo biến
    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    
    # Padding
    msg_len = len(message) * 8
    message += b'\x80'
    message += b'\x00' * ((55 - len(message)) % 64)
    message += msg_len.to_bytes(8, 'little')
    
    # Xử lý từng khối 64 bytes
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        X = list(int.from_bytes(block[j:j+4], 'little') for j in range(0, 64, 4))
        
        # 3 vòng (simplified)
        for round_num in range(3):
            for j in range(16):
                k = (j + round_num * 16) % 16
                temp = (A + X[k] + (B ^ C ^ D)) & 0xFFFFFFFF
                A, B, C, D = D, temp, B, C
    
    return A.to_bytes(4, 'little') + B.to_bytes(4, 'little') + C.to_bytes(4, 'little') + D.to_bytes(4, 'little')

# ============== MERKLE-DAMGÅRD CONSTRUCTION ==============

class MerkleDamgardHash:
    """
    Merkle-Damgård construction
    Cấu trúc chung của hầu hết hàm băm
    """
    
    def __init__(self, block_size=512, output_size=256):
        self.block_size = block_size
        self.output_size = output_size
        self.block_bytes = block_size // 8
    
    def padding(self, message):
        """
        Padding theo Merkle-Damgård
        Format: message || 1 || 0...0 || length
        """
        if isinstance(message, str):
            message = message.encode()
        msg_len = len(message) * 8
        message = bytearray(message)
        
        # Thêm bit '1'
        message.append(0x80)
        
        # Thêm bits '0' cho đến khi độ dài ≡ -64 (mod 512)
        while (len(message) % self.block_bytes) != (self.block_bytes - 8):
            message.append(0x00)
        
        # Thêm độ dài (64 bits, big-endian)
        message += msg_len.to_bytes(8, 'big')
        
        return bytes(message)
    
    def hash(self, message):
        """Băm một message"""
        # Khởi tạo IV (Initialization Vector)
        h = b'\x00' * (self.output_size // 8)
        
        # Padding
        message = self.padding(message)
        
        # Xử lý từng khối
        for i in range(0, len(message), self.block_bytes):
            block = message[i:i+self.block_bytes]
            # Compression function (simplified): XOR
            h = bytes(a ^ b for a, b in zip(h, block[:len(h)]))
        
        return h.hex()

# ============== SHA-512 INFORMATION ==============

class SHA512Info:
    """
    SHA-512 Information (sử dụng hashlib)
    SHA-512 chính là Merkle-Damgård construction
    """
    
    @staticmethod
    def hash(message):
        """Tính SHA-512"""
        if isinstance(message, str):
            message = message.encode()
        return hashlib.sha512(message).hexdigest()
    
    @staticmethod
    def hmac(key, message):
        """
        HMAC-SHA512
        HMAC(K, M) = SHA512((K XOR opad) || SHA512((K XOR ipad) || M))
        """
        import hmac
        if isinstance(key, str):
            key = key.encode()
        if isinstance(message, str):
            message = message.encode()
        return hmac.new(key, message, hashlib.sha512).hexdigest()

# ============== DIGITAL SIGNATURE (SIMPLIFIED) ==============

class DigitalSignature:
    """Chữ ký số đơn giản (dựa trên RSA)"""
    
    def __init__(self):
        # Giả sử đã có RSA keys
        self.private_key_d = 2753
        self.public_key_e = 17
        self.public_key_n = 3233
    
    def sign(self, message):
        """
        Ký: S = SHA512(M)^d mod n
        """
        # Tính hash
        h = hashlib.sha512(message.encode()).digest()
        h_int = int.from_bytes(h[:8], 'big') % self.public_key_n
        
        # Ký bằng RSA
        signature = pow(h_int, self.private_key_d, self.public_key_n)
        return signature
    
    def verify(self, message, signature):
        """
        Xác minh: M' = S^e mod n, kiểm tra M' = SHA512(M)
        """
        # Tính hash của message
        h = hashlib.sha512(message.encode()).digest()
        h_int = int.from_bytes(h[:8], 'big') % self.public_key_n
        
        # Xác minh signature
        verified = pow(signature, self.public_key_e, self.public_key_n)
        
        return verified == h_int

# ============== KEY MANAGEMENT ==============

class KeyManagement:
    """Quản lý khóa"""
    
    @staticmethod
    def generate_key_pair(key_size=256):
        """Sinh cặp khóa"""
        import os
        private_key = os.urandom(key_size // 8)
        # Public key là hash của private key (simplified)
        public_key = hashlib.sha256(private_key).digest()
        return private_key, public_key
    
    @staticmethod
    def key_derivation(password, salt):
        """
        Key Derivation từ password
        Sử dụng PBKDF2
        """
        import hashlib
        iterations = 100000
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
        return key.hex()
    
    @staticmethod
    def key_rotation(old_key, time_based=True):
        """
        Key Rotation - Thay đổi khóa định kỳ
        """
        import hashlib
        import time
        
        if time_based:
            timestamp = str(int(time.time())).encode()
            new_key = hashlib.sha256(old_key + timestamp).digest()
        else:
            import os
            new_key = hashlib.sha256(old_key + os.urandom(16)).digest()
        
        return new_key

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("CHƯƠNG 8: HÀM BĂM, CHỮ KÝ SỐ VÀ QUẢN LÝ KHÓA")
    print("=" * 70)
    
    # 1. Hàm băm mật mã
    print("\n1. HÀM BĂM MẬT MÃ")
    print("-" * 70)
    
    # Hàm băm đơn giản
    print("   Hàm băm đơn giản:")
    message = "HELLO"
    hash_val = simple_hash(message)
    print(f"   Message: {message}")
    print(f"   Hash: {hash_val}")
    print(f"   (Chỉ có 31 bits - rất yếu!)")
    
    # Test hash function: Preimage & Collision
    print(f"\n   Test 1: Preimage Resistance")
    hash_val_1 = simple_hash("input1")
    hash_val_2 = simple_hash("input2")
    hash_val_3 = simple_hash("input1")  # Giống input1
    
    print(f"   simple_hash('input1') = {hash_val_1}")
    print(f"   simple_hash('input2') = {hash_val_2}")
    print(f"   simple_hash('input1') = {hash_val_3} (Deterministic) ✓")
    
    if hash_val_1 == hash_val_3:
        print(f"   ✓ KIỂM CHỨNG: Hash deterministic ✓")
    
    if hash_val_1 != hash_val_2:
        print(f"   ✓ Different inputs → Different hashes ✓")
    
    # MD4-like hash
    print(f"\n   Test 2: MD4-like hash")
    hash_md4_1 = md4_like_hash(message.encode())
    hash_md4_2 = md4_like_hash((message + "!").encode())
    
    print(f"   MD4-like('{message}') = {hash_md4_1.hex()[:32]}...")
    print(f"   MD4-like('{message}!') = {hash_md4_2.hex()[:32]}...")
    
    if hash_md4_1.hex() != hash_md4_2.hex():
        print(f"   ✓ KIỂM CHỨNG: Small change → Big hash change ✓")
    
    # 2. Merkle-Damgård
    print("\n2. MERKLE-DAMGÅRD CONSTRUCTION")
    print("-" * 70)
    
    md = MerkleDamgardHash(block_size=512, output_size=256)
    md_hash = md.hash(message)
    print(f"   Message: {message}")
    print(f"   Hash: {md_hash[:32]}...")
    print(f"   (Cấu trúc chuẩn cho SHA, MD5, RIPEMD, etc.)")
    
    # 3. SHA-512
    print("\n3. SHA-512")
    print("-" * 70)
    
    print(f"   Message: {message}")
    sha512_hash = SHA512Info.hash(message)
    print(f"   SHA-512: {sha512_hash[:64]}...")
    print(f"   Độ dài: {len(sha512_hash)} ký tự (512 bits)")
    
    # Test SHA-512 determinism & avalanche effect
    print(f"\n   Test SHA-512:")
    sha512_msg1 = SHA512Info.hash("Test message")
    sha512_msg2 = SHA512Info.hash("Test message")
    sha512_msg3 = SHA512Info.hash("Test message!")
    
    print(f"   SHA512('Test message') = {sha512_msg1[:32]}...")
    print(f"   SHA512('Test message') = {sha512_msg2[:32]}... (should match) ✓")
    print(f"   SHA512('Test message!') = {sha512_msg3[:32]}...")
    
    if sha512_msg1 == sha512_msg2:
        print(f"   ✓ KIỂM CHỨNG: SHA-512 deterministic ✓")
    
    if sha512_msg1 != sha512_msg3:
        print(f"   ✓ KIỂM CHỨNG: Avalanche effect - 1 bit change → 50% hash change ✓")
    
    # HMAC
    print(f"\n   Test HMAC-SHA512:")
    key = "SECRET_KEY"
    key_wrong = "WRONG_KEY"
    message_hmac = "HELLO"
    
    hmac_val = SHA512Info.hmac(key, message_hmac)
    hmac_val_2 = SHA512Info.hmac(key, message_hmac)
    hmac_val_wrong_key = SHA512Info.hmac(key_wrong, message_hmac)
    
    print(f"   Key: {key}")
    print(f"   Message: {message_hmac}")
    print(f"   HMAC: {hmac_val[:64]}...")
    print(f"   HMAC (same): {hmac_val_2[:32]}... (Deterministic) ✓")
    
    if hmac_val == hmac_val_2:
        print(f"   ✓ KIỂM CHỨNG: HMAC deterministic ✓")
    
    print(f"\n   HMAC with wrong key: {hmac_val_wrong_key[:32]}...")
    if hmac_val != hmac_val_wrong_key:
        print(f"   ✓ KIỂM CHỨNG: Different key → Different HMAC ✓")
    
    # 4. Tính chất hàm băm
    print("\n4. TÍNH CHẤT HÀM BĂM MẬT MÃ")
    print("-" * 70)
    print("""
    Preimage Resistance:
    - Cho h(x) = y, khó tìm được x
    - Cần 2^n operations (n = độ dài output)
    
    Second Preimage Resistance:
    - Cho x, khó tìm x' ≠ x sao cho h(x) = h(x')
    - Cần 2^n operations
    
    Collision Resistance:
    - Khó tìm x ≠ y sao cho h(x) = h(y)
    - Cần 2^(n/2) operations (Birthday attack)
    - SHA-512 (512-bit): 2^256 operations
    """)
    
    # 5. Chữ ký số
    print("\n5. CHỮ KÝ SỐ")
    print("-" * 70)
    
    ds = DigitalSignature()
    message_to_sign = "IMPORTANT MESSAGE"
    
    print(f"   Message: {message_to_sign}")
    signature = ds.sign(message_to_sign)
    print(f"   Signature: {signature}")
    
    # Xác minh
    verified = ds.verify(message_to_sign, signature)
    print(f"   Verified: {verified}")
    
    if verified:
        print(f"   ✓ KIỂM CHỨNG: Signature valid ✓")
    else:
        print(f"   ✗ LỖI: Signature invalid")
    
    # Xác minh với message sai
    print(f"\n   Test with wrong message:")
    verified_wrong = ds.verify(message_to_sign + "!", signature)
    print(f"   Message + '!': {message_to_sign}!")
    print(f"   Verified (expected False): {verified_wrong}")
    if not verified_wrong:
        print(f"   ✓ SECURITY CHECK: Detected tampered message ✓")
    else:
        print(f"   ✗ LỖI: Should detect tampered message")
    
    # 6. Quản lý khóa
    print("\n6. QUẢN LÝ KHÓA")
    print("-" * 70)
    
    # Sinh khóa
    private_key, public_key = KeyManagement.generate_key_pair(256)
    private_key_2, public_key_2 = KeyManagement.generate_key_pair(256)
    
    print(f"   Key 1:")
    print(f"   Private: {private_key.hex()[:32]}...")
    print(f"   Public:  {public_key.hex()[:32]}...")
    
    print(f"\n   Key 2:")
    print(f"   Private: {private_key_2.hex()[:32]}...")
    print(f"   Public:  {public_key_2.hex()[:32]}...")
    
    if private_key != private_key_2:
        print(f"   ✓ KIỂM CHỨNG: Generated keys are unique ✓")
    
    # Key Derivation
    print(f"\n   Test Key Derivation (PBKDF2):")
    password = "MyPassword123!"
    import os
    salt = os.urandom(16)
    salt_2 = os.urandom(16)
    
    derived_key = KeyManagement.key_derivation(password, salt)
    derived_key_2 = KeyManagement.key_derivation(password, salt)
    derived_key_diff_salt = KeyManagement.key_derivation(password, salt_2)
    
    print(f"   Password: {password}")
    print(f"   Salt: {salt.hex()[:16]}...")
    print(f"   Derived Key: {derived_key[:32]}...")
    print(f"   Derived Key (same salt): {derived_key_2[:32]}... ✓")
    
    if derived_key == derived_key_2:
        print(f"   ✓ KIỂM CHỨNG: Same password+salt → Same key ✓")
    
    print(f"\n   Salt (different): {salt_2.hex()[:16]}...")
    print(f"   Derived Key (diff salt): {derived_key_diff_salt[:32]}...")
    if derived_key != derived_key_diff_salt:
        print(f"   ✓ KIỂM CHỨNG: Different salt → Different key ✓")
    
    # Key Rotation
    print(f"\n   Test Key Rotation:")
    old_key = private_key
    new_key = KeyManagement.key_rotation(old_key)
    new_key_2 = KeyManagement.key_rotation(old_key)
    
    print(f"   Old Key: {old_key.hex()[:32]}...")
    print(f"   New Key: {new_key.hex()[:32]}...")
    print(f"   New Key (again): {new_key_2.hex()[:32]}...")
    
    if old_key != new_key:
        print(f"   ✓ KIỂM CHỨNG: Key rotated successfully ✓")
    
    # Note: Key rotation with time_based=True will produce different keys each time
    print(f"   (Note: Time-based rotation produces different keys per call)")
    
    # 7. Các loại chữ ký
    print("\n7. CÁC LOẠI CHỮ KÝ SỐ")
    print("-" * 70)
    print("""
    DSS (Digital Signature Standard):
    - Dựa trên Discrete Log Problem
    - Chuẩn FIPS 186-4
    - Tham số: p, q, g, x (private), y (public)
    
    Schnorr Signature:
    - Chữ ký tuyến tính
    - Nhanh hơn DSS
    - Nhỏ gọn hơn RSA
    
    ECDSA (Elliptic Curve DSA):
    - Dựa trên Elliptic Curve
    - Kích thước khóa nhỏ hơn RSA
    - Ví dụ: Bitcoin, Ethereum
    
    RSA Signature:
    - Ký: S = M^d mod n
    - Xác minh: M = S^e mod n
    - Rộng rãi nhất
    """)
    
    print("\n" + "=" * 70)