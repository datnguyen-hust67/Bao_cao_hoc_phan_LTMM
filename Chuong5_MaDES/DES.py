#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chương 5: Hệ mật mã DES
5.1: Lịch sử DES
5.2: Cấu trúc DES
5.3: Tính chất DES
5.4: Điểm yếu DES
5.5: Triple DES, Double DES
"""

def permute(block, perm_table):
    """Áp dụng bảng hoán vị"""
    result = 0
    for i, pos in enumerate(perm_table):
        result |= ((block >> (len(perm_table) - pos)) & 1) << (len(perm_table) - 1 - i)
    return result

def split_halves(block, size):
    """Chia khối thành 2 nửa"""
    mask = (1 << (size // 2)) - 1
    left = block >> (size // 2)
    right = block & mask
    return left, right

def combine_halves(left, right, size):
    """Kết hợp 2 nửa"""
    return (left << (size // 2)) | right

class DES:
    """Triển khai DES"""
    
    # Bảng hoán vị ban đầu (IP)
    IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    
    # Hoán vị cuối cùng (IP^-1)
    IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
    
    # Bảng expansion (E)
    E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    
    # S-boxes (đơn giản hóa, chỉ S1)
    S_BOXES = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 0, 5],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
    ]
    
    # P-box
    P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    
    def __init__(self):
        self.round_keys = []
    
    def key_schedule(self, key):
        """Sinh khóa vòng từ khóa 64-bit"""
        # Đơn giản hóa: sinh 16 khóa vòng
        self.round_keys = []
        for i in range(16):
            round_key = ((key << (i + 1)) | (key >> (64 - i - 1))) & 0xFFFFFFFFFFFFFFFF
            self.round_keys.append(round_key >> 48)  # Lấy 48 bits
    
    def round_function(self, right, round_key):
        """Hàm vòng f"""
        # Mở rộng right từ 32 bits thành 48 bits
        expanded = 0
        for i, pos in enumerate(self.E):
            expanded |= ((right >> (32 - pos)) & 1) << (47 - i)
        
        # XOR với khóa vòng
        xored = expanded ^ round_key
        
        # Áp dụng S-boxes (đơn giản hóa)
        substituted = 0
        for i in range(8):
            chunk = (xored >> (42 - 6*i)) & 0x3F
            row = ((chunk >> 5) & 1) | (((chunk) & 1) << 1)
            col = (chunk >> 1) & 0xF
            output = self.S_BOXES[0][row][col]
            substituted |= (output << (28 - 4*i))
        
        # Áp dụng P-box
        permuted = 0
        for i, pos in enumerate(self.P):
            permuted |= ((substituted >> (32 - pos)) & 1) << (31 - i)
        
        return permuted
    
    def encrypt_block(self, plaintext, key):
        """Mã hóa một khối 64-bit"""
        # Sinh khóa vòng
        self.key_schedule(key)
        
        # Initial Permutation
        block = permute(plaintext, self.IP)
        left, right = split_halves(block, 64)
        
        # 16 vòng
        for i in range(16):
            new_left = right
            new_right = left ^ self.round_function(right, self.round_keys[i])
            left, right = new_left, new_right
        
        # Hoán đổi cuối cùng (right trước left)
        combined = combine_halves(right, left, 64)
        
        # Final Permutation
        ciphertext = permute(combined, self.IP_INV)
        
        return ciphertext
    
    def decrypt_block(self, ciphertext, key):
        """Giải mã một khối"""
        # Sinh khóa vòng
        self.key_schedule(key)
        
        # Reverse lại round keys cho decryption
        self.round_keys = self.round_keys[::-1]
        
        # Initial Permutation
        block = permute(ciphertext, self.IP)
        left, right = split_halves(block, 64)
        
        # 16 vòng (với round keys đảo ngược)
        for i in range(16):
            new_left = right
            new_right = left ^ self.round_function(right, self.round_keys[i])
            left, right = new_left, new_right
        
        # Hoán đổi cuối cùng (right trước left)
        combined = combine_halves(right, left, 64)
        
        # Final Permutation
        plaintext = permute(combined, self.IP_INV)
        
        return plaintext

class TripleDES:
    """Triple DES - Mã hóa DES 3 lần"""
    
    def __init__(self):
        self.des = DES()
    
    def encrypt(self, plaintext, key1, key2, key3=None):
        """
        Triple DES:
        C = DES-encrypt(DES-decrypt(DES-encrypt(P, K1), K2), K3)
        
        Nếu K3 không được cung cấp, K3 = K1
        """
        if key3 is None:
            key3 = key1
        
        # Encrypt với K1
        temp1 = self.des.encrypt_block(plaintext, key1)
        
        # Decrypt với K2
        temp2 = self.des.decrypt_block(temp1, key2)
        
        # Encrypt với K3
        ciphertext = self.des.encrypt_block(temp2, key3)
        
        return ciphertext
    
    def decrypt(self, ciphertext, key1, key2, key3=None):
        """Giải mã Triple DES"""
        if key3 is None:
            key3 = key1
        
        # Decrypt với K3
        temp1 = self.des.decrypt_block(ciphertext, key3)
        
        # Encrypt với K2
        temp2 = self.des.encrypt_block(temp1, key2)
        
        # Decrypt với K1
        plaintext = self.des.decrypt_block(temp2, key1)
        
        return plaintext

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("CHƯƠNG 5: HỆ MẬT MÃ DES")
    print("=" * 70)
    
    # 1. Lịch sử DES
    print("\n1. LỊCH SỬ DES")
    print("-" * 70)
    print(f"""
    - Được phát triển bởi IBM năm 1977
    - Được chấp nhận như chuẩn mã hóa của chính phủ Mỹ
    - Sử dụng: 64-bit plaintext, 56-bit key (8 bits parity), 16 vòng
    - Triển khai: Hardware (nhanh) và Software
    - Kích thước khối: 64 bits
    - Kích thước khóa: 56 bits (effective)
    """)
    
    # 2. Cấu trúc DES
    print("\n2. CẤU TRÚC DES")
    print("-" * 70)
    
    des = DES()
    plaintext = 0x0123456789ABCDEF
    key = 0x133457799BBCDFF1
    
    print(f"   Plaintext:  0x{plaintext:016X}")
    print(f"   Key:        0x{key:016X}")
    print(f"   Kích thước: 64-bit plaintext, 56-bit key")
    print(f"   Vòng: 16 vòng Feistel")
    
    # Mã hóa
    ciphertext = des.encrypt_block(plaintext, key)
    print(f"\n   Ciphertext: 0x{ciphertext:016X}")
    
    # Giải mã
    decrypted = des.decrypt_block(ciphertext, key)
    print(f"   Decrypted:  0x{decrypted:016X}")
    
    # Kiểm chứng
    if plaintext == decrypted:
        print(f"\n   ✓ KIỂM CHỨNG: Plaintext = Decrypted ✓")
    else:
        print(f"\n   ✗ LỖI: Plaintext ≠ Decrypted")
    
    # 3. Tính chất DES
    print("\n3. TÍNH CHẤT DES")
    print("-" * 70)
    print(f"""
    Ưu điểm:
    - Được kiểm chứng rộng rãi
    - Hiệu suất cao trên cả hardware và software
    - Cấu trúc rõ ràng, dễ triển khai
    
    Nhược điểm:
    - Kích thước khóa chỉ 56 bits (quá nhỏ cho ngày nay)
    - Kích thước khối 64 bits (dễ bị tấn công birthday)
    - Đã bị phá vỡ bằng brute force (1997-1998)
    """)
    
    # 4. Điểm yếu DES
    print("\n4. ĐIỂM YẾU CỦA DES")
    print("-" * 70)
    print(f"""
    Weak Keys:
    - Có 4 "weak keys" mà khi dùng làm khóa sẽ tạo ra những vòng key tương tự
    - Điều này làm giảm độ an toàn
    
    Brute Force Attack:
    - 2^56 ≈ 7.2 × 10^16 khóa có thể
    - EFF tìm khóa DES trong 56 giờ (1998)
    - Ngày nay: có thể trong vài giờ
    
    Kích thước khối nhỏ:
    - 64 bits dễ bị collision attacks
    - Cần thay thế bằng 128-bit blocks (AES)
    """)
    
    # 5. TEST CASES KHÁC
    print("\n5. TEST CASES KHÁC")
    print("-" * 70)
    
    test_cases = [
        (0x0000000000000000, 0x0000000000000000),
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        (0x0123456789ABCDEF, 0x0123456789ABCDEF),
    ]
    
    for i, (pt, k) in enumerate(test_cases, 1):
        ct = des.encrypt_block(pt, k)
        dt = des.decrypt_block(ct, k)
        status = "✓" if pt == dt else "✗"
        print(f"   Test {i}: Plaintext=0x{pt:016X}, Key=0x{k:016X}")
        print(f"            Ciphertext=0x{ct:016X}, Decrypted=0x{dt:016X} {status}")
    
    # 5. Triple DES
    print("\n5. TRIPLE DES (3DES)")
    print("-" * 70)
    
    triple_des = TripleDES()
    key1 = 0x0123456789ABCDEF
    key2 = 0xFEDCBA9876543210
    key3 = 0x0123456789ABCDEF  # Hoặc khác
    
    plaintext_3des = 0x0123456789ABCDEF
    
    print(f"   Plaintext:  0x{plaintext_3des:016X}")
    print(f"   Key1:       0x{key1:016X}")
    print(f"   Key2:       0x{key2:016X}")
    print(f"   Key3:       0x{key3:016X}")
    
    ciphertext_3des = triple_des.encrypt(plaintext_3des, key1, key2, key3)
    print(f"\n   Ciphertext: 0x{ciphertext_3des:016X}")
    
    decrypted_3des = triple_des.decrypt(ciphertext_3des, key1, key2, key3)
    print(f"   Decrypted:  0x{decrypted_3des:016X}")
    
    # Kiểm chứng
    if plaintext_3des == decrypted_3des:
        print(f"\n   ✓ KIỂM CHỨNG 3DES: Plaintext = Decrypted ✓")
    else:
        print(f"\n   ✗ LỖI: Plaintext ≠ Decrypted")
    
    # 6. So sánh Double vs Triple DES
    print("\n6. SO SÁNH")
    print("-" * 70)
    print(f"""
    Double DES (2DES):
    - C = DES(DES(P, K1), K2)
    - Bị tấn công Meet-in-the-middle
    - Tương đương với DES đơn (độ an toàn không tăng)
    - KHÔNG sử dụng trong thực tế
    
    Triple DES (3DES):
    - C = DES(DES^-1(DES(P, K1), K2), K3)
    - Tương thích với DES (khi K1=K2=K3)
    - Hiệu suất khoảng 1/3 so với AES
    - Vẫn được sử dụng trong một số hệ thống cũ
    
    Kích thước khóa hiệu quả:
    - Single DES: 56 bits
    - 2DES: 56 bits (do meet-in-the-middle attack)
    - 3DES: 112 bits (với 2 khóa) hoặc 168 bits (với 3 khóa)
    """)
    
    print("\n" + "=" * 70)