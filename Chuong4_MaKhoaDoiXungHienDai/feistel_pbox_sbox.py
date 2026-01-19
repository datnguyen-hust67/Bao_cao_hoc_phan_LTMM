#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chương 4: Mã khóa đối xứng hiện đại
4.1: Giới thiệu
4.2: Sơ đồ khối hệ mật
4.3: Mã khối chuyển vị
4.4: Luật hoán vị (Permutation)
4.5: Luật thay thế (Substitution)
4.6: P-boxes, S-boxes
4.7: Mạng Feistel

TEST CASES: 5 official test cases
"""

# ============== PERMUTATION (P-BOXES) ==============

def permutation_box(input_bits, permutation_table):
    """
    P-box (Permutation box)
    Đầu vào: 64 bits
    Đầu ra: 64 bits (theo bảng hoán vị)
    
    Ví dụ: permutation_table = [58, 50, 42, 34, 26, 18, 10, 2, ...]
    Bit ở vị trí 0 của output = bit ở vị trí 58-1 của input
    """
    output = 0
    for i, perm_idx in enumerate(permutation_table):
        if (input_bits >> (perm_idx - 1)) & 1:
            output |= (1 << (len(permutation_table) - 1 - i))
    return output

def expansion_box(input_bits, expansion_table):
    """
    Expansion P-box
    Mở rộng 32 bits thành 48 bits (DES)
    Một số bit được lặp lại
    """
    output = 0
    for i, exp_idx in enumerate(expansion_table):
        if (input_bits >> (exp_idx - 1)) & 1:
            output |= (1 << (len(expansion_table) - 1 - i))
    return output

def straight_pbox(input_bits, pbox_table):
    """Straight P-box - Chỉ hoán vị"""
    return permutation_box(input_bits, pbox_table)

def compression_pbox(input_bits, compression_table):
    """Compression P-box - Nén dữ liệu"""
    return permutation_box(input_bits, compression_table)

# ============== SUBSTITUTION (S-BOXES) ==============

# S-box từ DES S1
DES_S1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 0, 5],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

def substitution_box(input_6bits, sbox):
    """
    S-box: 6 bits → 4 bits
    Row = bit 0 và bit 5
    Column = bits 1-4
    """
    row = ((input_6bits >> 5) & 1) | (((input_6bits) & 1) << 1)
    col = (input_6bits >> 1) & 0xF
    return sbox[row][col]

# ============== FEISTEL NETWORK ==============

def feistel_round(left, right, round_key, sbox_tables=None, pbox_table=None):
    """
    Một vòng Feistel
    
    Công thức:
    L' = R
    R' = L XOR f(R, K)
    
    Trong đó f() là hàm round function (thường gồm P-boxes, S-boxes, XOR với key)
    """
    # Round function (đơn giản hóa)
    f_output = right ^ round_key
    
    # Nếu có S-boxes
    if sbox_tables:
        # Chia thành 8 khối 6-bit
        substituted = 0
        for i in range(8):
            input_6bits = (f_output >> (42 - 6*i)) & 0x3F
            output_4bits = substitution_box(input_6bits, sbox_tables[i] if isinstance(sbox_tables, list) else sbox_tables)
            substituted |= (output_4bits << (28 - 4*i))
        f_output = substituted
    
    new_left = right
    new_right = left ^ f_output
    
    return new_left, new_right

def feistel_encrypt(plaintext, keys, rounds=16):
    """
    Mã hóa Feistel (ví dụ DES)
    
    Công thức Feistel chuẩn:
    L_{i+1} = R_i
    R_{i+1} = L_i XOR f(R_i, K_i)
    """
    # Chia plaintext thành 2 nửa 32-bit
    left = (plaintext >> 32) & 0xFFFFFFFF
    right = plaintext & 0xFFFFFFFF
    
    # 16 vòng Feistel
    for i in range(rounds):
        f_output = (right ^ keys[i]) & 0xFFFFFFFF
        left, right = right, left ^ f_output
    
    # Kết hợp (swap đã diễn ra tự động trong vòng lặp)
    ciphertext = (left << 32) | right
    return ciphertext

def feistel_decrypt(ciphertext, keys, rounds=16):
    """
    Giải mã Feistel (ngược lại từng vòng)
    
    Để giải mã Feistel, chúng ta phải đảo ngược từng vòng:
    Từ (L_{i+1}, R_{i+1}) -> (L_i, R_i)
    R_i = L_{i+1}
    L_i = R_{i+1} XOR f(L_{i+1}, K_i)
    """
    # Chia ciphertext thành 2 nửa 32-bit
    left = (ciphertext >> 32) & 0xFFFFFFFF
    right = ciphertext & 0xFFFFFFFF
    
    # Đảo ngược 16 vòng Feistel (từ vòng 15 về vòng 0)
    for i in range(rounds - 1, -1, -1):
        f_output = (left ^ keys[i]) & 0xFFFFFFFF
        new_left = right ^ f_output
        new_right = left
        left, right = new_left, new_right
    
    # Kết hợp
    plaintext = (left << 32) | right
    return plaintext

# ============== MODERN BLOCK CIPHER STRUCTURE ==============

class BlockCipherStructure:
    """Cấu trúc chung của mã khối hiện đại"""
    
    def __init__(self, block_size=64, key_size=56):
        """
        block_size: kích thước khối (bit)
        key_size: kích thước khóa (bit)
        """
        self.block_size = block_size
        self.key_size = key_size
        self.rounds = 16
    
    def key_schedule(self, master_key):
        """Lịch sinh khóa - Sinh các khóa vòng từ master key"""
        round_keys = []
        for i in range(self.rounds):
            # Đơn giản hóa: xoay master key
            round_key = ((master_key << (i + 1)) | (master_key >> (self.key_size - i - 1))) & ((1 << self.key_size) - 1)
            round_keys.append(round_key)
        return round_keys
    
    def initial_permutation(self, plaintext):
        """Initial Permutation (IP)"""
        return plaintext
    
    def final_permutation(self, plaintext):
        """Final Permutation (IP^-1)"""
        return plaintext
    
    def encrypt(self, plaintext, key):
        """Mã hóa"""
        round_keys = self.key_schedule(key)
        ciphertext = self.initial_permutation(plaintext)
        ciphertext = feistel_encrypt(ciphertext, round_keys, self.rounds)
        ciphertext = self.final_permutation(ciphertext)
        return ciphertext
    
    def decrypt(self, ciphertext, key):
        """Giải mã"""
        round_keys = self.key_schedule(key)
        plaintext = self.initial_permutation(ciphertext)
        plaintext = feistel_decrypt(plaintext, round_keys, self.rounds)
        plaintext = self.final_permutation(plaintext)
        return plaintext

# ============================================================================
# MAIN - 5 OFFICIAL TEST CASES
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("CHƯƠNG 4: MÃ KHÓA ĐỐI XỨNG HIỆN ĐẠI")
    print("=" * 70)
    
    # ========== TEST 1: P-BOX (8-bit) ==========
    print("\n===== P-BOX (8-bit) =====")
    print("-" * 70)
    
    pbox_table = [8, 6, 4, 2, 7, 5, 3, 1]
    input_pbox = 0b10110010  # 0xB2
    output_pbox = permutation_box(input_pbox, pbox_table)
    
    print(f"Input:  {input_pbox:08b} (0x{input_pbox:02X})")
    print(f"Table:  {pbox_table}")
    print(f"Output: {output_pbox:08b} (0x{output_pbox:02X}) ✓")
    
    # ========== TEST 2: S-BOX (DES S1) ==========
    print("\n===== S-BOX (DES S1) =====")
    print("-" * 70)
    
    input_sbox = 0b011011  # 27 decimal
    output_sbox = substitution_box(input_sbox, DES_S1)
    
    row = ((input_sbox >> 5) & 1) | (((input_sbox) & 1) << 1)
    col = (input_sbox >> 1) & 0xF
    
    print(f"Input:  {input_sbox:06b} (6 bits) = {input_sbox}")
    print(f"Row:    {row}")
    print(f"Col:    {col}")
    print(f"Output: DES_S1[{row}][{col}] = {output_sbox} (4 bits) ✓")
    
    # ========== TEST 3: FEISTEL ROUND ==========
    print("\n===== FEISTEL ROUND =====")
    print("-" * 70)
    
    left = 0x12345678
    right = 0x9ABCDEF0
    round_key = 0xF00DBEEF
    
    print(f"Left:   0x{left:08X}")
    print(f"Right:  0x{right:08X}")
    print(f"Key:    0x{round_key:08X}")
    
    new_left, new_right = feistel_round(left, right, round_key)
    
    print(f"Output: L' = 0x{new_left:08X}, R' = 0x{new_right:08X} ✓")
    
    # ========== TEST 4: BLOCK CIPHER ENCRYPTION ==========
    print("\n===== BLOCK CIPHER ENCRYPTION =====")
    print("-" * 70)
    
    cipher = BlockCipherStructure(block_size=64, key_size=56)
    
    plaintext = 0x0123456789ABCDEF
    key = 0x0123456789ABCDEF
    
    print(f"Plaintext: 0x{plaintext:016X}")
    print(f"Key:       0x{key:016X}")
    print(f"Rounds:    {cipher.rounds}")
    
    ciphertext = cipher.encrypt(plaintext, key)
    print(f"Ciphertext: 0x{ciphertext:016X} ✓")
    
    # ========== TEST 5: DECRYPTION VERIFICATION ==========
    print("\n===== DECRYPTION VERIFICATION =====")
    print("-" * 70)
    
    decrypted = cipher.decrypt(ciphertext, key)
    
    print(f"Decrypted:  0x{decrypted:016X}")
    
    is_match = (decrypted == plaintext)
    print(f"Match:      {is_match} {'✓' if is_match else '✗'}")
    
    if not is_match:
        print(f"\nExpected:   0x{plaintext:016X}")
        print(f"Got:        0x{decrypted:016X}")
    
    print("\n" + "=" * 70)