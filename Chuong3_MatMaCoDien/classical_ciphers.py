#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CHƯƠNG 3: MẬT MÃ CỔ ĐIỂN (CLASSICAL CIPHERS)

Nội dung:
3.1 - Mã Chuyển Dịch (Caesar Cipher)
3.2 - Mã Thay Thế (Substitution Cipher)
3.3 - Mã Vigenère (Vigenère Cipher)
3.4 - Mã Hill (Hill Cipher)
3.5 - Mã Playfair (Playfair Cipher)
3.6 - Mã Rabin (Rabin Cipher)

THAM KHẢO TÀI LIỆU:
"An Introduction to Cryptography" - PGP Corporation
Trang 11: Caesar's cipher

Chạy: python 3_Classical_Ciphers.py
"""

import string
from collections import Counter

# ========== 3.1: MÃ CHUYỂN DỊch (SHIFT/CAESAR CIPHER) ==========

class CaesarCipher:
    """
    Mã Caesar (mã chuyển dịch)
    
    Nguyên lý:
    - Dịch mỗi ký tự đi k vị trí trong bảng chữ cái
    - Công thức mã hóa: C ≡ P + k (mod 26)
    - Công thức giải mã: P ≡ C - k (mod 26)
    
    Không gian khóa: 25 (k = 0..25)
    
    Độ an toàn: RẤT THẤP
    - Có thể brute force với 25 phép thử
    - Dễ frequency analysis
    
    Ví dụ (k = 3):
    PLAINTEXT → SODQWHBW
    """
    
    def __init__(self, shift=3):
        self.shift = shift % 26
    
    def encrypt(self, plaintext):
        result = []
        for char in plaintext.upper():
            if char.isalpha():
                pos = ord(char) - ord('A')
                encrypted = (pos + self.shift) % 26
                result.append(chr(encrypted + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, ciphertext):
        result = []
        for char in ciphertext.upper():
            if char.isalpha():
                pos = ord(char) - ord('A')
                decrypted = (pos - self.shift) % 26
                result.append(chr(decrypted + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def brute_force(ciphertext):
        """Tấn công brute force: thử tất cả 25 khóa"""
        results = {}
        for shift in range(26):
            cipher = CaesarCipher(shift)
            plaintext = cipher.decrypt(ciphertext)
            results[shift] = plaintext
        return results


# ========== 3.2: MÃ THAY THẾ (SUBSTITUTION CIPHER) ==========

class SubstitutionCipher:
    """
    Mã Thay Thế
    
    Nguyên lý:
    - Mỗi ký tự thay thế bằng ký tự khác cố định
    - Sử dụng bảng thay thế (substitution table)
    
    Không gian khóa: 26! ≈ 4 × 10^26
    Độ an toàn: Trung bình
    
    Điểm yếu:
    - Tần suất ký tự được bảo toàn
    - Dễ frequency analysis attack
    """
    
    def __init__(self, key=None):
        if key is None:
            # Atbash cipher: A↔Z, B↔Y, ...
            alpha = string.ascii_uppercase
            self.key = dict(zip(alpha, alpha[::-1]))
        else:
            self.key = key
        
        self.inverse_key = {v: k for k, v in self.key.items()}
    
    def encrypt(self, plaintext):
        result = []
        for char in plaintext.upper():
            if char in self.key:
                result.append(self.key[char])
            else:
                result.append(char)
        return ''.join(result)
    
    def decrypt(self, ciphertext):
        result = []
        for char in ciphertext.upper():
            if char in self.inverse_key:
                result.append(self.inverse_key[char])
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def frequency_analysis(text):
        """Phân tích tần suất ký tự"""
        chars = Counter(c for c in text.upper() if c.isalpha())
        return sorted(chars.items(), key=lambda x: x[1], reverse=True)


# ========== 3.3: MÃ VIGENÈRE (VIGENÈRE CIPHER) ==========

class VigenèreCipher:
    """
    Mã Vigenère
    
    Nguyên lý:
    - Mã dịch tuần hoàn với khóa đa ký tự
    - Công thức: C[i] = (P[i] + K[i mod m]) mod 26
    - m: độ dài khóa
    
    Không gian khóa: 26^m
    Độ an toàn: Cao hơn shift cipher
    
    Lịch sử:
    - Được coi là "le chiffre indéchiffrable"
    - Bị phá bởi Kasiski Examination
    
    Ví dụ:
    Plaintext:  ATTACKATDAWN
    Key:        SECRETSECRET
    Ciphertext: SRWWTAGRYAWV
    """
    
    def __init__(self, key):
        self.key = key.upper()
        self.key_len = len(self.key)
    
    def encrypt(self, plaintext):
        result = []
        key_idx = 0
        
        for char in plaintext.upper():
            if char.isalpha():
                shift = ord(self.key[key_idx % self.key_len]) - ord('A')
                pos = ord(char) - ord('A')
                encrypted = (pos + shift) % 26
                result.append(chr(encrypted + ord('A')))
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, ciphertext):
        result = []
        key_idx = 0
        
        for char in ciphertext.upper():
            if char.isalpha():
                shift = ord(self.key[key_idx % self.key_len]) - ord('A')
                pos = ord(char) - ord('A')
                decrypted = (pos - shift) % 26
                result.append(chr(decrypted + ord('A')))
                key_idx += 1
            else:
                result.append(char)
        
        return ''.join(result)


# ========== 3.4: MÃ HILL (HILL CIPHER) ==========

class HillCipher:
    """
    Mã Hill
    
    Nguyên lý:
    - Sử dụng ma trận để mã hóa khối ký tự
    - Công thức: C = K × P (mod 26)
    
    Độ an toàn: Cao
    Ứng dụng: Mã khối
    
    Điểm yếu:
    - Dễ ciphertext-plaintext attack
    - Yêu cầu ma trận khả nghịch
    """
    
    def __init__(self, key_matrix):
        self.key_matrix = key_matrix
        self.n = len(key_matrix)
        self.inv_matrix = self._compute_inverse()
    
    def _compute_inverse(self):
        """Tính ma trận nghịch đảo mod 26"""
        if self.n != 2:
            raise ValueError("Chỉ hỗ trợ ma trận 2×2")
        
        det = (self.key_matrix[0][0] * self.key_matrix[1][1] - 
               self.key_matrix[0][1] * self.key_matrix[1][0]) % 26
        
        def mod_inv(a, m):
            for i in range(1, m):
                if (a * i) % m == 1:
                    return i
            return None
        
        det_inv = mod_inv(det, 26)
        if det_inv is None:
            raise ValueError("Ma trận không khả nghịch")
        
        inv = [
            [(det_inv * self.key_matrix[1][1]) % 26,
             (-det_inv * self.key_matrix[0][1]) % 26],
            [(-det_inv * self.key_matrix[1][0]) % 26,
             (det_inv * self.key_matrix[0][0]) % 26]
        ]
        
        for i in range(2):
            for j in range(2):
                inv[i][j] = (inv[i][j] % 26 + 26) % 26
        
        return inv
    
    def encrypt(self, plaintext):
        plaintext = plaintext.upper()
        plaintext = ''.join(c for c in plaintext if c.isalpha())
        
        if len(plaintext) % self.n != 0:
            plaintext += 'X' * (self.n - len(plaintext) % self.n)
        
        result = []
        for i in range(0, len(plaintext), self.n):
            block = plaintext[i:i + self.n]
            block_vec = [ord(c) - ord('A') for c in block]
            
            cipher_vec = []
            for row in self.key_matrix:
                val = sum(row[j] * block_vec[j] for j in range(self.n)) % 26
                cipher_vec.append(val)
            
            result.extend(chr(c + ord('A')) for c in cipher_vec)
        
        return ''.join(result)
    
    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper()
        ciphertext = ''.join(c for c in ciphertext if c.isalpha())
        
        result = []
        for i in range(0, len(ciphertext), self.n):
            block = ciphertext[i:i + self.n]
            block_vec = [ord(c) - ord('A') for c in block]
            
            plain_vec = []
            for row in self.inv_matrix:
                val = sum(row[j] * block_vec[j] for j in range(self.n)) % 26
                plain_vec.append(val)
            
            result.extend(chr(c + ord('A')) for c in plain_vec)
        
        return ''.join(result)


# ========== 3.5: MÃ PLAYFAIR (PLAYFAIR CIPHER) ==========

class PlayfairCipher:
    """
    Mã Playfair
    
    Nguyên lý:
    - Sử dụng ma trận 5×5
    - Mã hóa cặp ký tự (digraph)
    
    Quy tắc:
    1. Cùng hàng → thay bằng ký tự bên phải
    2. Cùng cột → thay bằng ký tự dưới
    3. Hình chữ nhật → hoán đổi cột
    
    Độ an toàn: Cao hơn mã thay thế đơn
    """
    
    def __init__(self, key):
        self.key = key.upper()
        self.matrix = self._create_matrix()
        self.pos_map = self._create_pos_map()
    
    def _create_matrix(self):
        alpha = string.ascii_uppercase.replace('J', '')
        key_chars = []
        for c in self.key:
            if c.isalpha() and c not in key_chars and c != 'J':
                key_chars.append(c)
        
        matrix_chars = key_chars + [c for c in alpha if c not in key_chars]
        
        matrix = []
        for i in range(5):
            row = []
            for j in range(5):
                row.append(matrix_chars[i * 5 + j])
            matrix.append(row)
        
        return matrix
    
    def _create_pos_map(self):
        pos_map = {}
        for i in range(5):
            for j in range(5):
                pos_map[self.matrix[i][j]] = (i, j)
        return pos_map
    
    def _process_text(self, text):
        text = ''.join(c.upper() for c in text if c.isalpha())
        text = text.replace('J', 'I')
        
        result = []
        for c in text:
            if result and result[-1] == c:
                result.append('X')
            result.append(c)
        
        if len(result) % 2:
            result.append('X')
        
        return ''.join(result)
    
    def encrypt(self, plaintext):
        plaintext = self._process_text(plaintext)
        result = []
        
        for i in range(0, len(plaintext), 2):
            c1, c2 = plaintext[i], plaintext[i + 1]
            r1, c1_pos = self.pos_map[c1]
            r2, c2_pos = self.pos_map[c2]
            
            if r1 == r2:
                result.append(self.matrix[r1][(c1_pos + 1) % 5])
                result.append(self.matrix[r2][(c2_pos + 1) % 5])
            elif c1_pos == c2_pos:
                result.append(self.matrix[(r1 + 1) % 5][c1_pos])
                result.append(self.matrix[(r2 + 1) % 5][c2_pos])
            else:
                result.append(self.matrix[r1][c2_pos])
                result.append(self.matrix[r2][c1_pos])
        
        return ''.join(result)
    
    def decrypt(self, ciphertext):
        ciphertext = ''.join(c.upper() for c in ciphertext if c.isalpha())
        result = []
        
        for i in range(0, len(ciphertext), 2):
            c1, c2 = ciphertext[i], ciphertext[i + 1]
            r1, c1_pos = self.pos_map[c1]
            r2, c2_pos = self.pos_map[c2]
            
            if r1 == r2:
                result.append(self.matrix[r1][(c1_pos - 1) % 5])
                result.append(self.matrix[r2][(c2_pos - 1) % 5])
            elif c1_pos == c2_pos:
                result.append(self.matrix[(r1 - 1) % 5][c1_pos])
                result.append(self.matrix[(r2 - 1) % 5][c2_pos])
            else:
                result.append(self.matrix[r1][c2_pos])
                result.append(self.matrix[r2][c1_pos])
        
        return ''.join(result)


# ========== 3.6: MÃ RABIN (RABIN CIPHER) ==========

class RabinCipher:
    """
    Mã Rabin
    
    Nguyên lý:
    - Dựa trên bài toán căn bậc hai modulo n
    - Công thức: C ≡ P^2 (mod n)
    
    Độ an toàn: Tương đương RSA
    Điểm yếu: Có 4 plaintext cho 1 ciphertext (thường)
    """
    
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
    
    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = int(plaintext.encode().hex(), 16)
        
        if plaintext >= self.n:
            raise ValueError("Plaintext phải nhỏ hơn n")
        
        return (plaintext ** 2) % self.n
    
    def decrypt(self, ciphertext):
        def tonelli_shanks(a, p):
            """Trả về list các căn bậc hai của a mod p (nếu tồn tại), hoặc [] nếu không"""
            a = a % p
            if a == 0:
                return [0]
            # Kiểm tra xem a có phải quadratic residue mod p không
            if pow(a, (p - 1) // 2, p) != 1:
                return []
            
            # Trường hợp p ≡ 3 mod 4
            if p % 4 == 3:
                x = pow(a, (p + 1) // 4, p)
                return [x, (p - x) % p]
            
            # Trường hợp p ≡ 1 mod 4 - Tonelli-Shanks algorithm
            q = p - 1
            s = 0
            while q % 2 == 0:
                q //= 2
                s += 1
            
            # Tìm z là non-quadratic residue
            z = 2
            while pow(z, (p - 1) // 2, p) != p - 1:
                z += 1
            
            m = s
            c = pow(z, q, p)
            t = pow(a, q, p)
            r = pow(a, (q + 1) // 2, p)
            
            while True:
                if t == 0:
                    return [0]
                if t == 1:
                    return [r, (p - r) % p]
                
                # Tìm i nhỏ nhất sao cho t^(2^i) ≡ 1 mod p
                i = 1
                tt = (t * t) % p
                while tt != 1:
                    tt = (tt * tt) % p
                    i += 1
                    if i == m:
                        return []  # Không nên xảy ra nếu a là quadratic residue
                
                b = pow(c, 1 << (m - i - 1), p)
                r = (r * b) % p
                c = (b * b) % p
                t = (t * c) % p
                m = i
        
        mp = tonelli_shanks(ciphertext, self.p)
        mq = tonelli_shanks(ciphertext, self.q)
        
        if not mp or not mq:
            return []
        
        solutions = []
        p_inv = pow(self.p, -1, self.q)
        q_inv = pow(self.q, -1, self.p)
        
        for xp in mp:
            for xq in mq:
                # Chinese Remainder Theorem
                x = (xq * self.p * p_inv + xp * self.q * q_inv) % self.n
                solutions.append(x)
        
        return sorted(set(solutions))  # loại bỏ trùng lặp nếu có


# ========== TEST VÀ DEMO ==========

def main():
    print("╔" + "="*68 + "╗")
    print("║" + " CHƯƠNG 3: MẬT MÃ CỔ ĐIỂN ".center(68) + "║")
    print("╚" + "="*68 + "╝")
    
    # Test 1: Caesar Cipher
    print("\n[TEST 3.1] MÃ CHUYỂN DỊch (CAESAR)")
    print("="*70)
    plaintext = "HELLO WORLD"
    caesar = CaesarCipher(3)
    ciphertext = caesar.encrypt(plaintext)
    decrypted = caesar.decrypt(ciphertext)
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Đúng!" if decrypted == plaintext else "✗ Sai!")
    
    # Test 2: Substitution
    print("\n[TEST 3.2] MÃ THAY THẾ (SUBSTITUTION)")
    print("="*70)
    plaintext = "CRYPTOGRAPHY"
    sub = SubstitutionCipher()
    ciphertext = sub.encrypt(plaintext)
    decrypted = sub.decrypt(ciphertext)
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Đúng!" if decrypted == plaintext else "✗ Sai!")
    
    # Test 3: Vigenère
    print("\n[TEST 3.3] MÃ VIGENÈRE")
    print("="*70)
    plaintext = "ATTACKATDAWN"
    key = "SECRET"
    vigenere = VigenèreCipher(key)
    ciphertext = vigenere.encrypt(plaintext)
    decrypted = vigenere.decrypt(ciphertext)
    print(f"Plaintext:  {plaintext}")
    print(f"Key:        {key}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Đúng!" if decrypted == plaintext else "✗ Sai!")
    
    # Test 4: Hill
    print("\n[TEST 3.4] MÃ HILL")
    print("="*70)
    plaintext = "HELIX"
    key_matrix = [[5, 8], [3, 5]]
    try:
        hill = HillCipher(key_matrix)
        ciphertext = hill.encrypt(plaintext)
        decrypted = hill.decrypt(ciphertext)
        print(f"Plaintext:  {plaintext}")
        print(f"Ciphertext: {ciphertext}")
        print(f"Decrypted:  {decrypted}")
        print(f"✓ Đúng!" if plaintext in decrypted else "✗ Sai!")
    except Exception as e:
        print(f"Lỗi: {e}")
    
    # Test 5: Playfair
    print("\n[TEST 3.5] MÃ PLAYFAIR")
    print("="*70)
    plaintext = "SECRETMESSAGE"
    key = "MONARCHY"
    playfair = PlayfairCipher(key)
    ciphertext = playfair.encrypt(plaintext)
    decrypted = playfair.decrypt(ciphertext)
    print(f"Plaintext:  {plaintext}")
    print(f"Key:        {key}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    
    # Trong hàm main(), thay phần Test 6 bằng đoạn sau:

    # Test 6: Rabin
    print("\n[TEST 3.6] MÃ RABIN")
    print("="*70)
    p, q = 61, 53
    rabin = RabinCipher(p, q)
    plaintext = 42
    ciphertext = rabin.encrypt(plaintext)
    solutions = rabin.decrypt(ciphertext)
    print(f"p={p}, q={q}, n={rabin.n}")
    print(f"Plaintext:   {plaintext}")
    print(f"Ciphertext:  {ciphertext}")
    print(f"Solutions:   {solutions}")
    print(f"✓ Đúng!" if plaintext in solutions else "✗ Sai!")
    
    print("\n" + "="*70)
    print("✓ HỌC XONG CHƯƠNG 3!")
    print("="*70)


if __name__ == "__main__":
    main()