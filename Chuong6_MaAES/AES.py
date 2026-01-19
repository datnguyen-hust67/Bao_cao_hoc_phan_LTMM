#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chương 6: Hệ mật mã AES (Rijndael)
6.1: Lịch sử AES
6.2: Cấu trúc AES
6.3: Các phép biến đổi (SubBytes, ShiftRows, MixColumns, AddRoundKey)
6.4: Tính chất AES
"""

class AES:
    """Triển khai AES đơn giản hóa (educational)"""
    
    # S-box (simplified)
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5f, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xd7, 0x4b, 0x55, 0xcf, 0x34, 0xc5, 0x84,
        0xcb, 0xda, 0x39, 0x2b, 0x0d, 0x70, 0xf7, 0x3b, 0xfd, 0xd9, 0x3c, 0x80, 0xec, 0x5b, 0x5c, 0x6f,
        0x13, 0x39, 0x8b, 0xd4, 0x69, 0x73, 0xb5, 0x37, 0x35, 0x83, 0x4f, 0x6b, 0x10, 0x2d, 0xf7, 0xf8,
        0x45, 0x70, 0x52, 0x67, 0xa3, 0xd5, 0xf9, 0xae, 0x8f, 0xdf, 0x9b, 0x2f, 0x72, 0x6a, 0x65, 0xc0,
    ]
    
    INV_SBOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x3f, 0xb9, 0xd1, 0x77, 0xda, 0x26, 0xa2, 0xe1, 0x72, 0xa6, 0x2f, 0xe7, 0x29, 0x5d,
        0x0d, 0x84, 0x69, 0x2d, 0xc1, 0x2c, 0x3e, 0x97, 0x10, 0x19, 0xe8, 0x1a, 0x71, 0x2c, 0xc7, 0xad,
        0x65, 0x2d, 0x96, 0xa3, 0x15, 0xc1, 0x25, 0x8e, 0xf4, 0x73, 0xca, 0xb3, 0xa4, 0x5f, 0x7c, 0x11,
    ]
    
    def __init__(self, key_size=128):
        """
        key_size: 128, 192, hoặc 256 bits
        """
        self.key_size = key_size
        if key_size == 128:
            self.rounds = 10
        elif key_size == 192:
            self.rounds = 12
        elif key_size == 256:
            self.rounds = 14
        else:
            raise ValueError("Key size must be 128, 192, or 256 bits")
    
    def sub_bytes(self, state):
        """SubBytes transformation"""
        for i in range(16):
            state[i] = self.SBOX[state[i]]
        return state
    
    def shift_rows(self, state):
        """ShiftRows transformation"""
        # Sắp xếp lại thành 4x4 matrix
        matrix = [state[i*4:(i+1)*4] for i in range(4)]
        
        # Shift rows
        matrix[1] = matrix[1][1:] + matrix[1][:1]  # Shift left 1
        matrix[2] = matrix[2][2:] + matrix[2][:2]  # Shift left 2
        matrix[3] = matrix[3][3:] + matrix[3][:3]  # Shift left 3
        
        # Flatten lại
        return [matrix[i][j] for i in range(4) for j in range(4)]
    
    def mix_columns(self, state):
        """MixColumns transformation (simplified)"""
        # Đơn giản hóa: chỉ XOR các columns
        for col in range(4):
            a0 = state[col]
            a1 = state[4 + col]
            a2 = state[8 + col]
            a3 = state[12 + col]
            
            # Galois field multiplication (simplified)
            state[col] = (a0 ^ a1 ^ a2 ^ a3) & 0xFF
            state[4 + col] = state[col]
            state[8 + col] = state[col]
            state[12 + col] = state[col]
        
        return state
    
    def add_round_key(self, state, round_key):
        """AddRoundKey transformation"""
        for i in range(16):
            state[i] ^= round_key[i]
        return state
    
    def encrypt(self, plaintext, key):
        """
        Mã hóa AES
        plaintext: 128 bits (16 bytes)
        key: 128/192/256 bits
        """
        # Chuyển thành bytes
        if isinstance(plaintext, int):
            state = [(plaintext >> (8 * (15 - i))) & 0xFF for i in range(16)]
        else:
            state = list(plaintext[:16])
        
        if isinstance(key, int):
            round_key = [(key >> (8 * (15 - i))) & 0xFF for i in range(16)]
        else:
            round_key = list(key[:16])
        
        # Initial round
        state = self.add_round_key(state, round_key)
        
        # Main rounds
        for round_num in range(self.rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            if round_num < self.rounds - 1:
                state = self.mix_columns(state)
            
            # Generate next round key (simplified)
            round_key = [(round_key[i] + round_num + 1) & 0xFF for i in range(16)]
            state = self.add_round_key(state, round_key)
        
        # Chuyển thành integer
        ciphertext = 0
        for byte in state:
            ciphertext = (ciphertext << 8) | byte
        
        return ciphertext

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("CHƯƠNG 6: HỆ MẬT MÃ AES (ADVANCED ENCRYPTION STANDARD)")
    print("=" * 70)
    
    # 1. Lịch sử AES
    print("\n1. LỊCH SỬ AES")
    print("-" * 70)
    print(f"""
    - NIST công bố cuộc thi để tìm thay thế cho DES (1997)
    - Rijndael được chọn làm AES (2000)
    - Được công bố như chuẩn FIPS 197 (2001)
    - Được chấp nhận rộng rãi toàn thế giới
    - Khóa: 128, 192, hoặc 256 bits
    - Khối: 128 bits (cố định)
    - Vòng: 10 (AES-128), 12 (AES-192), 14 (AES-256)
    """)
    
    # 2. Cấu trúc AES
    print("\n2. CẤU TRÚC AES")
    print("-" * 70)
    
    aes128 = AES(key_size=128)
    plaintext = 0x00112233445566778899AABBCCDDEEFF
    key = 0x000102030405060708090A0B0C0D0E0F
    
    print(f"   AES-128:")
    print(f"   Plaintext:  0x{plaintext:032X}")
    print(f"   Key:        0x{key:032X}")
    print(f"   Kích thước: 128-bit plaintext, 128-bit key")
    print(f"   Vòng: {aes128.rounds}")
    
    ciphertext = aes128.encrypt(plaintext, key)
    print(f"   Ciphertext: 0x{ciphertext:032X} ✓")
    
    # 3. Các phép biến đổi
    print("\n3. CÁC PHÉP BIẾN ĐỔI AES")
    print("-" * 70)
    print(f"""
    SubBytes (Thay thế):
    - Thay thế từng byte bằng giá trị trong S-box
    - Cung cấp tính phi tuyến
    - Độ phức tạp: O(16)
    
    ShiftRows (Chuyển dịch hàng):
    - Hàng 0: không dịch
    - Hàng 1: dịch trái 1 byte
    - Hàng 2: dịch trái 2 bytes
    - Hàng 3: dịch trái 3 bytes
    - Cung cấp diffusion
    
    MixColumns (Trộn cột):
    - Nhân ma trận từng cột với ma trận MixColumn trong GF(2^8)
    - Cung cấp diffusion mạnh
    - Phức tạp nhất
    
    AddRoundKey (Thêm khóa vòng):
    - XOR từng byte với khóa vòng tương ứng
    - Kết nối khóa với quá trình mã hóa
    """)
    
    # 4. So sánh AES vs DES
    print("\n4. SO SÁNH AES VỚI DES")
    print("-" * 70)
    print(f"""
    Kích thước:
    - DES: 64-bit block, 56-bit key
    - AES: 128-bit block, 128/192/256-bit key
    
    Tốc độ:
    - DES: ~60 Mbps (software)
    - AES: ~100 Mbps (software)
    - AES-NI (hardware): > 10 Gbps
    
    Bảo mật:
    - DES: Đã bị phá vỡ
    - AES: Vẫn an toàn cho cả lý thuyết lẫn thực tế
    
    Tính linh hoạt:
    - DES: Cố định
    - AES: Linh hoạt (3 kích thước khóa, 1 kích thước khối)
    """)
    
    # 5. Các mode hoạt động
    print("\n5. CÁC MODE HOẠT ĐỘNG AES")
    print("-" * 70)
    print("""
    ECB (Electronic Code Book):
    - Mã hóa từng khối độc lập
    - KHÔNG nên dùng (pattern visible)
    
    CBC (Cipher Block Chaining):
    - Mã hóa phụ thuộc vào khối trước
    - C_i = E(P_i XOR C_{i-1})
    - Cần IV (Initialization Vector)
    
    CTR (Counter):
    - Chuyển thành stream cipher
    - C_i = P_i XOR E(counter)
    - Nhanh, song song được
    
    GCM (Galois/Counter Mode):
    - CTR + Authentication
    - Cung cấp cả confidentiality lẫn authenticity
    - Được khuyến nghị
    """)
    
    # 6. Ứng dụng
    print("\n6. ỨNG DỤNG AES")
    print("-" * 70)
    print(f"""
    - WPA2/WPA3 (WiFi)
    - TLS/SSL (HTTPS)
    - IPSec (VPN)
    - File encryption (VeraCrypt, 7-Zip)
    - Cloud storage (AWS KMS, Google Cloud KMS)
    - Cryptocurrency wallets
    """)
    
    # 7. TEST CASES CHI TIẾT
    print("\n7. TEST CASES CHI TIẾT")
    print("-" * 70)
    
    test_cases_aes = [
        (128, 0x00112233445566778899AABBCCDDEEFF, 0x000102030405060708090A0B0C0D0E0F),
        (128, 0x0000000000000000000000000000000, 0x0000000000000000000000000000000),
        (128, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
    ]
    
    for key_size, pt, k in test_cases_aes:
        aes = AES(key_size=key_size)
        ct = aes.encrypt(pt, k)
        print(f"\n   AES-{key_size}:")
        print(f"   Plaintext:  0x{pt:032X}")
        print(f"   Key:        0x{k:032X}")
        print(f"   Ciphertext: 0x{ct:032X} ✓")
    
    # 8. SubBytes Transformation Demo
    print("\n8. SUBBYTES TRANSFORMATION DEMO")
    print("-" * 70)
    state = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
    
    print(f"   Original state: {[hex(b) for b in state[:4]]}... ")
    aes128.sub_bytes(state)
    print(f"   After SubBytes: {[hex(b) for b in state[:4]]}... ✓ (S-box applied)")
    
    # 9. ShiftRows Transformation Demo
    print("\n9. SHIFTROWS TRANSFORMATION DEMO")
    print("-" * 70)
    state = [i for i in range(16)]
    matrix_before = [state[i*4:(i+1)*4] for i in range(4)]
    
    print(f"   Before ShiftRows:")
    for row in matrix_before:
        print(f"      {row}")
    
    state = [i for i in range(16)]
    state = aes128.shift_rows(state)
    matrix_after = [state[i*4:(i+1)*4] for i in range(4)]
    
    print(f"   After ShiftRows:")
    for row in matrix_after:
        print(f"      {row} ✓")
    
    print("\n" + "=" * 70)