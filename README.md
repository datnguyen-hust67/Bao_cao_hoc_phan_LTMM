# BÁO CÁO QUÁ TRÌNH VÀ TỔNG HỢP KIẾN THỨC HỌC PHẦN LÝ THUYẾT MẬT MÃ

**Sinh viên:** Nguyễn Thành Đạt
**MSSV:** 20223688 
**Lớp:** Tài năng ĐTVT K67 HUST 
**Học phần:** Lý thuyết mật mã  
**Mục đích:** Báo cáo quá trình và tổng hợp kiến thức môn Lý Thuyết Mật Mã 

---

## 📋 MỤC LỤC

1. [Chương 1: Đánh giá quá trình và các phần kiến thức](#chương-1-đánh-giá-quá-trình-và-các-phần-kiến-thức)
2. [Chương 2: Cơ Sở Toán Học](#chương-2-cơ-sở-toán-học)
3. [Chương 3: Mã Cổ Điển](#chương-3-mã-cổ-điển)
4. [Chương 4: Mã Khóa Đối Xứng Hiện Đại](#chương-4-mã-khóa-đối-xứng-hiện-đại)
5. [Chương 5: Mã DES](#chương-5-des)
6. [Chương 6: Mã AES](#chương-6-aes)
7. [Chương 7: Mã RSA](#chương-8-mã-rsa)
8. [Chương 8: Hàm Băm & Chữ Ký Số](#chương-8-hàm-băm--chữ-ký-số)
9. [Kết luận](#kết-luận)

---

## Chương 1: Tự đánh giá quá trình và các phần kiến thức đạt được 

### 1.1 Đánh giá quá trình

#### a) Về chuyên cần
- Trong 16 tuần học, em vắng 1 buổi học 
- 15 tuần còn lại em đi học đầy đủ và tích cực trong giờ học, hoàn thành các nhiệm vụ mà thầy và anh giao trên lớp
- Bài tập về nhà em nộp đầy đủ, đúng hạn được giao
#### b) Về làm việc với nhóm
- Nhóm em đã cùng nhau làm và trình bày trước lớp 3 lần, trong đó
+ 1 lần xung phong trình bày vễ mã AES trước lớp
+ 1 lần xung phong trình bày về Bài tập lớn giữa kỳ
+ 1 lần báo cáo vào cuối kỳ 
- Trong các buổi nhóm trình bày, em đều có mặt đầy đủ và trình bày cùng các bạn
#### c) Về nhiệm vụ bài tập lớn
- Nhóm em gồm 3 bạn đã phát triển được ứng dụng ChatNet giúp tăng cường bảo mật tin nhắn bằng 4 loại mã hóa AES, DES, RSA, Caesar, hỗ trợ gửi tin nhắn văn bản, hình ảnh và tập file, đồng thời nhóm cũng đã tìm hiểu và phát triển tính năng mã hóa và gửi video, tuy nhiên do dung lượng video lớn cùng với thời gian có hạn, nên nhóm chưa hoàn thiện được tính năng này. Trong thời gian tới, nhóm sẽ tiếp tục tìm tòi và phát triển thêm.
- Trong bài tập lớn, em làm được 40% trên tổng khối lượng công việc. ​

### 1.2 Các kiến thức tích lũy được

Trong 16 tuần học, dưới sự hướng dẫn của thầy PGS.TS Đỗ Trọng Tuấn và anh Ma Việt Đức, cùng với sự tìm tòi và đọc thêm tài liệu, em đã tích lũy được những phần kiến thức sau:

1. **Chương 2** - Cơ sở toán học
   - GCD & Extended GCD (Bezout Lemma)
   - Modular Inverse & CRT
   - Factorization & Primality Testing
   
2. **Chương 3** - Mã cổ điển
   - Caesar Cipher Brute Force
   - Vigenère Frequency Analysis (Kasiski, IC)
   - Affine Cipher
   
3. **Chương 5** - Mã DES
   - Cấu trúc Feistel chi tiết
   - Key Schedule & Weak Keys
   - Meet-in-the-Middle Attack on 2DES
   
4. **Chương 6** - Mã AES
   - SubBytes, ShiftRows, MixColumns
   - Galois Field Arithmetic
   - So sánh DES vs AES
5. **Chương 7** - Mã khóa bất đối xứng  
   - Lý thuyết mã khóa bất đối xứng
   - Hàm trapdoor function
   - Hybrid Encryption 
6. **Chương 8** - Mã RSA
   - Sinh khóa: Chọn p, q, tính e, d
   - Ví dụ tính toán chi tiết
   - Các tấn công: Brute Force, Factorization, Small Exponent
   - Meet-in-the-Middle Attack
   
7. **Chương 9** - Hash & Signature
   - Merkle-Damgård Construction
   - SHA-512 & HMAC chi tiết
   - Tính chất: Preimage, 2nd Preimage, Collision Resistance

### 1.3 Phạm vi và mục tiêu của việc tổng hợp

#### a) Phạm vi
| Chương | Chủ đề | Thuật Toán | 
|--------|--------|-----------|
| 2 | Cơ sở toán học | GCD, Extended GCD, CRT, RSA key | 
| 3 | Mã cổ điển | Caesar, Vigenère, Hill, Playfair | 
| 4 | Feistel & Boxes | P-box, S-box, DES structure |
| 5 | DES | DES encryption, Triple DES | 
| 6 | AES | SubBytes, ShiftRows, MixColumns | 
| 6.5 | Asymmetric theory | Trapdoor function, Public/Private key | 
| 7 | Public key | RSA, ElGamal, Knapsack | 
| 8 | Hash & Signature | SHA-512, HMAC, Digital Signature |

#### b) Mục tiêu 
✅**Nắm được lý Thuyết để ứng dụng cho công việc cũng như thi:**
   - Công thức toán học chi tiết
   - Ví dụ tính toán từng bước
   - Phân tích bảo mật và tấn công
   - So sánh các phương pháp
   - Ứng dụng thực tế cụ thể

✅ **Nâng cao kỹ năng code python và hiểu thuật toán** (Từ Scratch)
   - Không dùng thư viện mã hóa
   - Giúp hiểu rõ cơ chế hoạt động
   - Thực hiện các thuật toán chuẩn

✅ **Tạo test cases đầy đủ để hiểu hơn**
   - Mỗi thuật toán có test case
   - Kiểm chứng đúng/sai rõ ràng
   - Ví dụ known plaintext

---

## CHƯƠNG 2: CƠ SỞ TOÁN HỌC

### 2.1 Số Học Các Số Nguyên 

#### **A. Ước Số Chung Lớn Nhất (GCD) - Thuật Toán Euclid**

**Định nghĩa:**
- GCD(a,b) là số nguyên dương lớn nhất chia hết cả a và b
- Ký hiệu: gcd(a,b) hoặc (a,b)

**Thuật Toán Euclid:**
```
GCD(a, b):
  if b = 0:
    return a
  else:
    return GCD(b, a mod b)
```

**Ví dụ tính toán:**
```
GCD(48, 18):
  48 = 18 × 2 + 12     → GCD(18, 12)
  18 = 12 × 1 + 6      → GCD(12, 6)
  12 = 6 × 2 + 0       → GCD(6, 0)
  Return 6
```

**Độ phức tạp:** O(log min(a,b))
- Trường hợp xấu nhất: Fibonacci numbers
- GCD(F(n), F(n-1)) cần n lần lặp, F(n) ~ φ^n, nên O(log φ^n) = O(n)

**Tính chất quan trọng:**
1. gcd(a, b) = gcd(b, a) - Giao hoán
2. gcd(a, b) = gcd(a, b mod a) - Tính chất modulo
3. gcd(a, 0) = a - Trường hợp cơ sở
4. Bổ đề Bezout: ∃ x,y ∈ ℤ: ax + by = gcd(a,b)

**Hàm thực hiện:**
```python
      def gcd_euclidean(a, b):
        """
        Thuật toán Euclid tìm ƯSCLN
        Công thức: gcd(a, b) = gcd(b, a mod b) cho đến khi b = 0
        Độ phức tạp: O(log(min(a,b)))
        
        Ví dụ: gcd(48, 18)
        48 = 18*2 + 12
        18 = 12*1 + 6
        12 = 6*2 + 0
        → gcd = 6
        """
        while b != 0:
            a, b = b, a % b
        return a
```

---

#### **B. Extended GCD (Euclid Mở Rộng)**

**Mục đích:** Không chỉ tìm gcd(a,b), mà còn tìm x, y sao cho:
```
ax + by = gcd(a,b)
```

**Thuật Toán:**
```
Extended_GCD(a, b):
  if b = 0:
    return (a, 1, 0)  # gcd=a, x=1, y=0
  else:
    (g, x1, y1) = Extended_GCD(b, a mod b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)
```

**Ví dụ chi tiết:**
```
Extended_GCD(48, 18):

Bước 1: a=48, b=18, a mod b = 12
  Gọi Extended_GCD(18, 12)

Bước 2: a=18, b=12, a mod b = 6
  Gọi Extended_GCD(12, 6)

Bước 3: a=12, b=6, a mod b = 0
  Gọi Extended_GCD(6, 0)
  Return (6, 1, 0)  # 6*1 + 0*0 = 6 ✓

Bước 3 quay lại: g=6, x1=1, y1=0
  x = 0
  y = 1 - (12//6)*0 = 1
  Return (6, 0, 1)  # 12*0 + 6*1 = 6 ✓

Bước 2 quay lại: g=6, x1=0, y1=1
  x = 1
  y = 0 - (18//12)*1 = -1
  Return (6, 1, -1)  # 18*1 + 12*(-1) = 6 ✓

Bước 1 quay lại: g=6, x1=1, y1=-1
  x = -1
  y = 1 - (48//18)*(-1) = 1 + 2 = 3
  Return (6, -1, 3)  # 48*(-1) + 18*3 = -48 + 54 = 6 ✓
```

**Ứng dụng quan trọng:**
1. **Tính Modular Inverse**: Tìm a⁻¹ mod m
   - Nếu gcd(a,m)=1, thì Extended_GCD(a,m) = (1, x, y)
   - a*x + m*y = 1
   - a*x ≡ 1 (mod m)
   - Vậy a⁻¹ ≡ x (mod m)

2. **Giải phương trình Diophantine**: ax + by = c
   - Nếu c chia hết cho gcd(a,b), có vô số nghiệm
   - Nghiệm tổng quát: x = x₀ + (b/gcd)*t, y = y₀ - (a/gcd)*t

**Hàm thực hiện:**
```python
      def gcd_extended(a, b):
        """
        Thuật toán Euclid mở rộng
        Tìm ƯSCLN và các hệ số x, y sao cho: a*x + b*y = gcd(a,b)
        
        Trả về: (gcd, x, y)
        
        Ứng dụng:
        - Tìm phần tử nghịch đảo trong số học mô đun
        - Giải phương trình đồng dư tuyến tính
        """
        if b == 0:
            return a, 1, 0
        else:
            gcd, x1, y1 = MathematicsBasics.gcd_extended(b, a % b)
            x = y1
            y = x1 - (a // b) * y1
            return gcd, x, y
```

**Kết quả thực nghiệm:**
![Kết quả 1](/home/lenovo/cryptography_project/results/test1_gcd_extendedGCD.png)

---

#### **C. Số Nguyên Tố và Kiểm Tra Nguyên Tố**

**Định nghĩa:**
- Số nguyên tố p: Chỉ có ước số là 1 và p, p > 1
- Ví dụ: 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, ...

**Kiểm tra nguyên tố - Phương pháp đơn giản:**
```
is_prime(n):
  if n < 2: return False
  if n = 2: return True
  if n % 2 = 0: return False
  for i = 3 to √n step 2:
    if n % i = 0: return False
  return True
```

**Độ phức tạp:** O(√n)

**Ví dụ:**
- is_prime(17): √17 ≈ 4.1
  - Kiểm tra: 3 → 17 % 3 = 2 (OK)
  - Không cần kiểm tra 5 (> 4.1)
  - Kết luận: 17 là nguyên tố ✓

**Kiểm tra nguyên tố nâng cao:**
1. **Miller-Rabin** (Xác suất): O(k log n) với độ chính xác 1 - 4^(-k)
2. **Lucas-Lehmer** (Mersenne primes): Chuyên dụng
3. **AKS Primality** (Đa thức): O(log^6 n) nhưng chậm trong thực tế

**Hàm thực hiện:**
```python
      def is_prime_simple(n):
        """
        Kiểm tra số nguyên tố - phương pháp đơn giản
        Độ phức tạp: O(√n)
        
        Một số nguyên tố là số tự nhiên > 1 không có ước ngoài 1 và chính nó
        """
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        
        # Kiểm tra từ 3 đến √n
        for i in range(3, int(n**0.5) + 1, 2):
            if n % i == 0:
                return False
        return True
    
      def is_prime_fermat(n, k=5):
        """
        Kiểm tra số nguyên tố - Fermat's Little Theorem
        Nếu p là số nguyên tố thì: a^(p-1) ≡ 1 (mod p) với gcd(a, p) = 1
        
        Độ chính xác: cao nhưng không 100% (có số Carmichael)
        k: số lần lặp (càng cao càng chính xác)
        """
        import random
        
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        for _ in range(k):
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False
        return True
```
**Kết quả thực nghiệm:**
![Kết quả 2](/home/lenovo/cryptography_project/results/test2_snt.png)
---

#### **D. Phân Tích Thừa Số Nguyên Tố (Factorization)**

**Bài toán:** Cho n, tìm n = p₁^a₁ × p₂^a₂ × ... × pₖ^aₖ

**Phương pháp 1: Trial Division**
```
Factorization(n):
  factors = []
  for i = 2 to √n:
    while n % i = 0:
      factors.append(i)
      n = n / i
  if n > 1:
    factors.append(n)
  return factors
```

**Ví dụ:**
```
Factorization(60):
  60 % 2 = 0 → factors = [2], n = 30
  30 % 2 = 0 → factors = [2,2], n = 15
  15 % 2 ≠ 0 → i = 3
  15 % 3 = 0 → factors = [2,2,3], n = 5
  5 % 3 ≠ 0, i > √5, n = 5 > 1
  factors = [2,2,3,5]
  Result: 60 = 2² × 3 × 5
```

**Độ phức tạp:** O(√n)

**Phương pháp 2: Pollard's Rho**
- Độ phức tạp: O(n^(1/4))
- Dùng cho n là tích hai số nguyên tố lớn

**Khó khăn:**
- Factorization là bài toán NP (trong số các bài toán tính toán)
- Không có thuật toán đa thức nhanh chóng
- RSA dựa vào độ khó này!

**Hàm thực hiện:**
```python
      def prime_factors(n):
        """
        Phân tích n thành thừa số nguyên tố
        Ví dụ: 60 = 2^2 * 3 * 5
        Độ phức tạp: O(√n)
        """
        factors = []
        d = 2
        
        while d * d <= n:
            while n % d == 0:
                factors.append(d)
                n //= d
            d += 1
        
        if n > 1:
            factors.append(n)
        
        return factors
```
**Kết quả thực nghiệm:**
![Kết quả 3](/home/lenovo/cryptography_project/results/test3_ptsnt.png)
---

### 2.2 Số Học Module 

#### **A. Phép Tính Module**

**Định nghĩa:** a ≡ b (mod m) nếu m | (a - b)

**Tính chất:**
```
1. Nếu a ≡ b (mod m) và c ≡ d (mod m):
   - a + c ≡ b + d (mod m)
   - a - c ≡ b - d (mod m)
   - a × c ≡ b × d (mod m)

2. Nếu a ≡ b (mod m):
   - a^n ≡ b^n (mod m) với n ≥ 0

3. Nếu d | m:
   - a ≡ b (mod m) ⇒ a ≡ b (mod d)
```

**Ví dụ:**
```
17 ≡ 5 (mod 12)  (vì 17 - 5 = 12, 12|12)
3 ≡ 15 (mod 12)  (vì 3 - 15 = -12, 12|-12)
17 ≡ 5 (mod 12) ⇒ 17 ≡ 5 (mod 4)  (4|12)
```

**Hàm thực hiện:**
```python
      def modular_addition(a, b, m):
        """
        Phép cộng mô đun: (a + b) mod m
        Tính chất: (a mod m + b mod m) mod m = (a + b) mod m
        """
        return (a + b) % m
    
      def modular_subtraction(a, b, m):
        """
        Phép trừ mô đun: (a - b) mod m
        Chú ý: Kết quả luôn không âm
        """
        return (a - b) % m
    
      def modular_multiplication(a, b, m):
        """
        Phép nhân mô đun: (a * b) mod m
        Tính chất: (a mod m) * (b mod m) mod m = (a * b) mod m
        """
        return (a * b) % m
    
      def modular_exponentiation(base, exp, mod):
        """
        Tính base^exp mod mod hiệu quả (Square and Multiply)
        Độ phức tạp: O(log(exp))
        
        Nguyên lý: Biểu diễn exp dưới dạng nhị phân
        Ví dụ: 2^10 mod 1000
        10 = 1010₂ = 8 + 2
        2^10 = 2^8 * 2^2
        """
        result = 1
        base = base % mod
        
        while exp > 0:
            # Nếu exp là lẻ
            if exp % 2 == 1:
                result = (result * base) % mod
            
            # Bình phương cơ số, chia đôi exponent
            exp = exp >> 1  # Chia cho 2
            base = (base * base) % mod
        
        return result
```
**Kết quả thực nghiệm:**
![Kết quả 4](/home/lenovo/cryptography_project/results/test4.png)

---

#### **B. Modular Inverse (Phần Tử Nghịch Đảo)**

**Định nghĩa:** a⁻¹ mod m là giá trị x sao cho:
```
a × x ≡ 1 (mod m)
```

**Điều kiện tồn tại:**
```
gcd(a, m) = 1  (a và m nguyên tố cùng nhau)
```

**Cách tính bằng Extended GCD:**
```
Extended_GCD(a, m) = (1, x, y)
→ a×x + m×y = 1
→ a×x ≡ 1 (mod m)
→ a⁻¹ ≡ x (mod m)
```

**Ví dụ:**
```
Tìm 7⁻¹ mod 26:
Extended_GCD(7, 26):
  26 = 7 × 3 + 5
  7 = 5 × 1 + 2
  5 = 2 × 2 + 1
  2 = 1 × 2 + 0

Quay lại:
  1 = 5 - 2 × 2
    = 5 - (7 - 5 × 1) × 2
    = 5 - 7 × 2 + 5 × 2
    = 5 × 3 - 7 × 2
    = (26 - 7 × 3) × 3 - 7 × 2
    = 26 × 3 - 7 × 9 - 7 × 2
    = 26 × 3 - 7 × 11
    = 7 × (-11) + 26 × 3

Vậy: 7 × (-11) ≡ 1 (mod 26)
     7 × 15 ≡ 1 (mod 26)  (vì -11 + 26 = 15)

Kiểm tra: 7 × 15 = 105 = 26 × 4 + 1 ✓
```

**Hàm thực hiện:**
```python
      def modular_inverse(a, m):
        """
        Tìm nghịch đảo mô đun của a mod m
        Tìm x sao cho: a*x ≡ 1 (mod m)
        
        Điều kiện: gcd(a, m) = 1
        Sử dụng Extended Euclidean Algorithm
        
        Ứng dụng: Giải phương trình đồng dư tuyến tính
        """
        gcd, x, _ = MathematicsBasics.gcd_extended(a, m)
        
        if gcd != 1:
            return None  # Nghịch đảo không tồn tại
        
        return (x % m + m) % m
```
**Kết quả thực nghiệm:**
![Kết quả 5](/home/lenovo/cryptography_project/results/test5.png)
---

#### **C. Định Lý Phần Dư Trung Hoa (Chinese Remainder Theorem - CRT)**

**Phát biểu:**
```
Nếu m₁, m₂, ..., mₖ nguyên tố cùng nhau từng đôi một:
hệ phương trình:
  x ≡ a₁ (mod m₁)
  x ≡ a₂ (mod m₂)
  ...
  x ≡ aₖ (mod mₖ)

có nghiệm duy nhất modulo M = m₁ × m₂ × ... × mₖ:
  x ≡ Σᵢ aᵢ × Mᵢ × (Mᵢ⁻¹ mod mᵢ) (mod M)

trong đó Mᵢ = M / mᵢ
```

**Ví dụ:**
```
Giải hệ:
  x ≡ 2 (mod 3)
  x ≡ 3 (mod 5)

M = 3 × 5 = 15
M₁ = 15 / 3 = 5    → 5⁻¹ mod 3 = 2  (vì 5 ≡ 2 (mod 3), 2×2=4≡1)
M₂ = 15 / 5 = 3    → 3⁻¹ mod 5 = 2  (vì 3×2=6≡1)

x ≡ 2×5×2 + 3×3×2 (mod 15)
  ≡ 20 + 18 (mod 15)
  ≡ 38 (mod 15)
  ≡ 8 (mod 15)

Kiểm tra:
  8 ≡ 2 (mod 3) ✓ (8 = 2×3 + 2)
  8 ≡ 3 (mod 5) ✓ (8 = 1×5 + 3)
```

**Ứng dụng:**
1. **RSA Decryption**: Tính M = C^d mod n nhanh hơn bằng CRT
2. **Tối ưu**: Thay vì 1 phép luỹ thừa mod n, dùng 2 phép mod p, q nhỏ hơn

---

### 2.3 Đồng dư tuyến tính

#### **A. Phương trình đồng dư tuyến tính**

**Định nghĩa:**
```
Giải phương trình: ax ≡ b (mod m)
Tìm giá trị x sao cho phương trình thỏa mãn
```

**Điều kiện giải:**
```
1. Nếu gcd(a, m) = 1:
   → Có đúng 1 nghiệm duy nhất
   → x ≡ a⁻¹ × b (mod m)

2. Nếu gcd(a, m) = d và d | b:
   → Có d nghiệm
   → Nghiệm tổng quát: x = x₀ + k(m/d), k = 0, 1, ..., d-1

3. Nếu gcd(a, m) = d và d ∤ b:
   → Vô nghiệm (không tồn tại x)
```

**Ví dụ chi tiết:**
```
Ví dụ 1: 3x ≡ 9 (mod 12)
  gcd(3, 12) = 3, 9 chia hết cho 3 ✓
  Chia nhỏ: x ≡ 3 (mod 4)
  Nghiệm: x ∈ {3, 7, 11} (3 nghiệm)

Ví dụ 2: 7x ≡ 5 (mod 26)
  gcd(7, 26) = 1 ✓
  Tìm 7⁻¹ mod 26 = 15 (vì 7×15 = 105 = 4×26 + 1)
  x ≡ 15 × 5 ≡ 75 ≡ 23 (mod 26)
  Kiểm tra: 7×23 = 161 = 6×26 + 5 ✓

Ví dụ 3: 2x ≡ 3 (mod 8)
  gcd(2, 8) = 2, nhưng 3 không chia hết cho 2
  → Vô nghiệm ✗
```

**Hàm thực hiện:**
```python
def solve_linear_congruence(a, b, m):
    """
    Giải phương trình đồng dư: ax ≡ b (mod m)
    
    Điều kiện giải:
    - Nếu gcd(a, m) = d và d | b: Có d nghiệm
    - Nếu gcd(a, m) = 1: Có đúng 1 nghiệm duy nhất
    - Nếu gcd(a, m) = d và d ∤ b: Vô nghiệm
    
    Ứng dụng:
    - Affine cipher: ax ≡ b (mod 26)
    - Hill cipher: Ax ≡ b (mod 26)
    
    Trả về: Danh sách các nghiệm hoặc []
    """
    d = gcd(a, m)
    
    # Kiểm tra điều kiện giải
    if b % d != 0:
        return []  # Vô nghiệm
    
    # Chia nhỏ bài toán
    a1 = a // d
    b1 = b // d
    m1 = m // d
    
    # Tìm x₀ từ: a1*x0 ≡ b1 (mod m1) với gcd(a1, m1) = 1
    a1_inv = mod_inverse(a1, m1)
    x0 = (a1_inv * b1) % m1
    
    # Tất cả nghiệm: x = x0 + k*(m/d), k = 0, 1, ..., d-1
    solutions = []
    for k in range(d):
        solutions.append(x0 + k * m1)
    
    return solutions
```
**Kết quả thực nghiệm:**
![Kết quả 6](/home/lenovo/cryptography_project/results/test6.png)

#### **B. Ứng Dụng: Affine Cipher**

**Định nghĩa:**
```
Mã hóa: E(x) = (ax + b) mod 26
Giải mã: D(y) = a⁻¹(y - b) mod 26
```

**Điều kiện:**
- `gcd(a, 26) = 1` (để a⁻¹ tồn tại)
- `a ∈ {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}` (12 giá trị hợp lệ)
- `b ∈ {0, 1, ..., 25}` (26 giá trị)
- **Tổng khóa:** 12 × 26 = 312 khóa

**Ví dụ chi tiết:**
```
Mã hóa với a=5, b=8:
E(x) = (5x + 8) mod 26

'H' → x=7:
  E(7) = (5×7 + 8) mod 26 = 43 mod 26 = 17 → 'R'

Giải mã 'R' → y=17:
  a⁻¹ = 5⁻¹ mod 26 = 21 (vì 5×21 = 105 = 4×26 + 1)
  D(17) = 21×(17 - 8) mod 26 = 21×9 mod 26 = 189 mod 26 = 7 → 'H' ✓
```

**Hàm thực hiện:**
```python
def affine_cipher_encrypt(plaintext, a, b):
    """
    Mã hóa Affine cipher
    E(x) = (ax + b) mod 26
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            x = ord(char.upper()) - ord('A')
            y = (a * x + b) % 26
            ciphertext += chr(y + ord('A'))
        else:
            ciphertext += char
    return ciphertext

def affine_cipher_decrypt(ciphertext, a, b):
    """
    Giải mã Affine cipher
    D(y) = a⁻¹(y - b) mod 26
    """
    a_inv = mod_inverse(a, 26)
    if a_inv == -1:
        return None
    
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('A'))
        else:
            plaintext += char
    return plaintext
```

### 2.4 Ma Trận (Matrix Operations)

#### **A. Phép Toán Ma Trận Cơ Bản**

**1. Phép Cộng Ma Trận:**
```
C[i][j] = (A[i][j] + B[i][j]) mod m
```

**2. Phép Trừ Ma Trận:**
```
C[i][j] = (A[i][j] - B[i][j]) mod m
```

**3. Phép Nhân Ma Trận:**
```
C[i][j] = Σₖ (A[i][k] × B[k][j]) mod m
Độ phức tạp: O(n³)
```

**Ví dụ nhân ma trận:**
```
A = [1 2]    B = [5 6]
    [3 4]        [7 8]

C[0][0] = 1×5 + 2×7 = 19
C[0][1] = 1×6 + 2×8 = 22
C[1][0] = 3×5 + 4×7 = 43
C[1][1] = 3×6 + 4×8 = 50

C = [19 22]
    [43 50]
```

**Hàm thực hiện:**
```python
def matrix_multiply(A, B, mod=None):
    """
    Nhân hai ma trận
    C[i][j] = Σ(A[i][k] * B[k][j]) mod
    
    Độ phức tạp: O(n³) phương pháp Naive
    
    Ứng dụng: Hill cipher encryption
    """
    m, n = len(A), len(A[0])
    p, q = len(B), len(B[0])
    
    assert n == p, "Matrix dimensions incompatible for multiplication"
    
    C = [[0] * q for _ in range(m)]
    
    for i in range(m):
        for j in range(q):
            for k in range(n):
                C[i][j] += A[i][k] * B[k][j]
            if mod:
                C[i][j] %= mod
    
    return C
```

#### **B. Định Thức Ma Trận (Determinant)**

**Ma trận 2×2:**
```
     |a b|
det |c d| = ad - bc
```

**Ma trận 3×3 (Quy tắc Sarrus):**
```
     |a b c|
det |d e f| = a(ei - fh) - b(di - fg) + c(dh - eg)
     |g h i|
```

**Ví dụ:**
```
     |2 3|
det |4 5| = 2×5 - 3×4 = 10 - 12 = -2

Mod 26: -2 ≡ 24 (mod 26)
```

**Hàm thực hiện:**
```python
def matrix_determinant_2x2(A):
    """
    Tính định thức ma trận 2x2
    det(A) = a*d - b*c
    
    Ứng dụng: Kiểm tra Hill cipher khóa khả nghịch
    """
    assert len(A) == 2 and len(A[0]) == 2, "Matrix must be 2x2"
    return A[0][0] * A[1][1] - A[0][1] * A[1][0]

def matrix_determinant_3x3(A):
    """
    Tính định thức ma trận 3x3
    det(A) = a(ei-fh) - b(di-fg) + c(dh-eg)
    """
    assert len(A) == 3 and len(A[0]) == 3, "Matrix must be 3x3"
    
    a, b, c = A[0]
    d, e, f = A[1]
    g, h, i = A[2]
    
    return a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)
```

#### **C. Ma Trận Nghịch Đảo (Inverse Matrix)**

**Định nghĩa:**
```
A × A⁻¹ ≡ I (mod m)
trong đó I là ma trận đơn vị
```

**Điều kiện tồn tại:**
```
gcd(det(A), m) = 1
Tức là: det(A) phải khả nghịch mod m
```

**Ma trận 2×2:**
```
A = [a b]
    [c d]

A⁻¹ = 1/det(A) × [ d -b]
                  [-c  a]

Mod m:
A⁻¹ ≡ (det(A))⁻¹ × [ d -b] (mod m)
                    [-c  a]
```

**Ví dụ chi tiết:**
```
A = [1 2]
    [3 5]

det(A) = 1×5 - 2×3 = -1 ≡ 25 (mod 26)
det(A)⁻¹ = 25⁻¹ mod 26 = 25 (vì 25×25 = 625 = 24×26 + 1)

A⁻¹ ≡ 25 × [ 5 -2] ≡ [ 125  -50] ≡ [21 24] (mod 26)
           [-3  1]    [-75   25]    [3  25]

Kiểm tra: A × A⁻¹ ≡ I (mod 26) ✓
```

**Hàm thực hiện:**
```python
def matrix_inverse_2x2(A, mod):
    """
    Tính ma trận nghịch đảo 2x2 (mod m)
    
    Công thức:
    A⁻¹ = 1/det(A) × [d -b; -c a]
    
    Điều kiện: gcd(det(A), m) = 1
    """
    det = (A[0][0] * A[1][1] - A[0][1] * A[1][0]) % mod
    det_inv = mod_inverse(det, mod)
    
    if det_inv == -1:
        return None  # Không có ma trận nghịch đảo
    
    # Công thức: det_inv × [d -b; -c a]
    return [
        [(det_inv * A[1][1]) % mod, (-det_inv * A[0][1]) % mod],
        [(-det_inv * A[1][0]) % mod, (det_inv * A[0][0]) % mod]
    ]
```
**Kết quả thực nghiệm:**
![Kết quả 7-8](/home/lenovo/cryptography_project/results/test7_8.png)

#### **D. Ứng Dụng: Hill Cipher**

**Định nghĩa:**
```
Mã hóa: C ≡ K × P (mod 26)
Giải mã: P ≡ K⁻¹ × C (mod 26)

trong đó:
- K: ma trận khóa (2×2 hoặc 3×3)
- P: ma trận plaintext
- C: ma trận ciphertext
```

**Ví dụ 2×2:**
```
Khóa K = [1 2]
         [3 5]

Mã hóa "HELP":
HE → [7, 4]ᵀ
LP → [11, 15]ᵀ

C ≡ K × P (mod 26):
C ≡ [1 2] × [7]  ≡ [7+8]   ≡ [15] (mod 26) → 'P'
    [3 5]   [4]    [21+20]   [15]           → 'P'

So ciphertext: "PPXX" (sau khi mã hóa hết)
```

**Hàm thực hiện:**
```python
def hill_cipher_encrypt(plaintext, key, block_size=2):
    """
    Mã hóa Hill cipher
    C ≡ K × P (mod 26)
    
    Điều kiện: gcd(det(K), 26) = 1
    """
    # Chuẩn bị plaintext (padding nếu cần)
    plaintext = plaintext.upper().replace(" ", "")
    if len(plaintext) % block_size != 0:
        plaintext += "X" * (block_size - len(plaintext) % block_size)
    
    ciphertext = ""
    
    # Mã hóa từng block
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        # Chuyển sang ma trận
        p = [[ord(c) - ord('A')] for c in block]
        # Nhân với khóa
        c = matrix_multiply(key, p, mod=26)
        # Chuyển sang text
        for j in range(block_size):
            ciphertext += chr(c[j][0] + ord('A'))
    
    return ciphertext

def hill_cipher_decrypt(ciphertext, key, key_inv, block_size=2):
    """
    Giải mã Hill cipher
    P ≡ K⁻¹ × C (mod 26)
    """
    ciphertext = ciphertext.upper()
    plaintext = ""
    
    # Giải mã từng block
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        # Chuyển sang ma trận
        c = [[ord(char) - ord('A')] for char in block]
        # Nhân với ma trận nghịch đảo
        p = matrix_multiply(key_inv, c, mod=26)
        # Chuyển sang text
        for j in range(block_size):
            plaintext += chr(p[j][0] + ord('A'))
    
    return plaintext
```

---

## CHƯƠNG 3: MÃ CỔ ĐIỂN (CLASSICAL CIPHERS)

### Giới thiệu

Mã cổ điển là các hệ mã hoạt động trên ký tự (character-level), được sáng tạo trước thời máy tính. 
Hầu hết đều đã bị phá vỡ nhưng có giá trị giáo dục cao để hiểu rõ cơ chế mã hóa.

---

### 3.1 Caesar Cipher - Brute Force Attack

####  **A. Lý Thuyết**

**Định nghĩa:**
```
Mã hóa: E(x) = (x + k) mod 26
Giải mã: D(y) = (y - k) mod 26
```

**Đặc điểm:**
- Caesar dịch mỗi ký tự đi k vị trí cố định
- Chỉ có 26 khóa có thể (k = 0 đến 25)
- k = 0: không mã hóa
- k = 13: ROT13 (thường dùng trong thực tế)
- Rất dễ bị brute force

**Ví dụ:**
```
Plaintext: HELLO
k = 3:
H → (7 + 3) mod 26 = 10 → K
E → (4 + 3) mod 26 = 7 → H
L → (11 + 3) mod 26 = 14 → O
L → (11 + 3) mod 26 = 14 → O
O → (14 + 3) mod 26 = 17 → R

Ciphertext: KHOOR ✓
```

####  **B. Brute Force Attack**

**Phương pháp:**
```
for k = 0 to 25:
  M' = Decrypt(C, k)
  if M' là text tiếng Anh:
    return k
```

**Phương pháp nhận diện text:**

1. **Chi-squared test:** Kiểm tra phân phối tần số
   ```
   χ² = Σ (observed - expected)² / expected
   
   Nếu χ² nhỏ → Có thể là text hợp lệ
   ```

2. **Entropy:** Ngôn ngữ tự nhiên có entropy < random
   ```
   H = -Σ pᵢ log₂(pᵢ)
   
   Tiếng Anh: ~4.7 bits/ký tự
   Random: ~5.0 bits/ký tự
   ```

3. **Từ điển:** Kiểm tra xem có từ hợp lệ không
   ```
   Nếu decrypt_text chứa nhiều từ hợp lệ → khóa đúng
   ```

####  **C. Ví Dụ Chi Tiết**

```
Ciphertext: "KHOOR ZRUOG"

Brute force thử k = 0 đến 25:
k = 0: KHOOR ZRUOG (không hợp lệ)
k = 1: JGNNQ YQTNF (không hợp lệ)
k = 2: IFMMP XPUMC (không hợp lệ)
k = 3: HELLO WORLD ✓ (từ điển: HELLO, WORLD hợp lệ!)

Tìm thấy: KHOOR ZRUOG → HELLO WORLD (k = 3)
```

####  **D. Hàm Thực Hiện**

```python
def caesar_encrypt(plaintext, k):
    """Mã hóa Caesar"""
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + k) % 26
            ciphertext += chr(shifted + base)
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, k):
    """Giải mã Caesar"""
    return caesar_encrypt(ciphertext, -k)

def caesar_brute_force(ciphertext, dictionary=None):
    """
    Tấn công brute force Caesar
    Thử tất cả 26 khóa và kiểm tra hợp lệ
    """
    for k in range(26):
        decrypted = caesar_decrypt(ciphertext, k)
        
        # Phương pháp 1: Kiểm tra từ điển
        if dictionary and all(word in dictionary for word in decrypted.split()):
            return k, decrypted
        
        # Phương pháp 2: Chi-squared test
        chi_squared = calculate_chi_squared(decrypted)
        if chi_squared < THRESHOLD:
            return k, decrypted
    
    return None, None
```

**Độ phức tạp:** O(26 × n) = O(n) tuyến tính → Rất yếu! ✗

####  **E. Kết Quả Kiểm Thử**

```
Caesar Cipher Brute Force:
Ciphertext: KHOOR ZRUOG
Trying k = 0: KHOOR ZRUOG (chi_squared = 2845.3) ✗
Trying k = 1: JGNNQ YQTNF (chi_squared = 3012.1) ✗
...
Trying k = 3: HELLO WORLD (chi_squared = 12.5) ✓

Result: k = 3, Plaintext = HELLO WORLD ✓
```

**Kết quả thực nghiệm:**
![Kết quả 9](/home/lenovo/cryptography_project/results/test3.1.png)

### 3.2 Mã Thay Thế (Substitution Cipher)

####  **A. Lý Thuyết**

**Định nghĩa:**
```
Tạo bảng thay thế: A → Q, B → P, C → M, ...
Mã hóa: Thay thế từng ký tự theo bảng
```

**Đặc điểm:**
- Bảng thay thế có 26! ≈ 4 × 10²⁶ khóa có thể
- Che giấu tần số ký tự tốt hơn Caesar
- Nhưng vẫn có thể bị tấn công frequency analysis

####  **B. Ví Dụ**

```
Bảng thay thế:
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Q W E R T Y U I O P A S D F G H J K L Z X C V B N M

Plaintext: HELLO
H → I, E → T, L → D, L → D, O → O
Ciphertext: ITDDO
```

####  **C. Hàm Thực Hiện**

```python
def substitution_encrypt(plaintext, key):
    """Mã hóa thay thế"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            idx = ord(char.upper()) - ord('A')
            ciphertext += key[idx]
        else:
            ciphertext += char
    return ciphertext

def substitution_decrypt(ciphertext, key):
    """Giải mã thay thế"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            idx = key.index(char)
            plaintext += alphabet[idx]
        else:
            plaintext += char
    return plaintext
```

**Độ phức tạp tấn công:** O(26! × n) ≈ không khả thi bằng brute force ✗

**Kết quả thực nghiệm:**
![Kết quả 10](/home/lenovo/cryptography_project/results/test3.2.png)

### 3.3 Vigenère Cipher - Polyalphabetic Cipher

####  **A. Lý Thuyết**

**Định nghĩa:**
```
Với khóa K = k₁k₂...kₘ (độ dài m):
E(pᵢ) = (pᵢ + k_{(i mod m)}) mod 26
D(cᵢ) = (cᵢ - k_{(i mod m)}) mod 26
```

**Đặc điểm:**
- Mỗi vị trí có shift khác nhau
- Che giấu tần số ký tự đơn lẻ (polyalphabetic)
- Caesar là trường hợp đặc biệt khi độ dài khóa = 1
- Được coi là "unbreakable" trong 300 năm!

####  **B. Ví Dụ Chi Tiết**

```
Plaintext: HELLO WORLD
Key: KEY (lặp lại: K E Y K E Y K E Y K)

Mã hóa:
H + K(10) → R
E + E(4)  → I
L + Y(24) → J
L + K(10) → V
O + E(4)  → S

(Tương tự cho WORLD)

Ciphertext: RIJVS UYVJN

Nhận xét: HELLO → RIJVS nhưng WORLD → UYVJN
          Cùng từ nhưng khác ciphertext!
```

####  **C. Tấn Công 1: Kasiski Examination**

**Nguyên lý:**
- Nếu cứ mỗi m ký tự lặp lại thì có cơ hội cao là cùng shift
- Khoảng cách giữa chuỗi lặp lại thường là bội số của m

**Phương pháp:**
```
1. Tìm các chuỗi 2-3 ký tự lặp lại
2. Tính khoảng cách giữa chúng
3. Tính GCD(khoảng cách) → Độ dài khóa m
```

**Ví dụ:**
```
Ciphertext: "THE QUICK BROWN FOX THE LAZY DOG"
                          ↓
           "THE" lặp lại ở vị trí 0 và 24
           Khoảng cách = 24
           
Thử m = 1,2,3,4,6,8,12,24
Những m nào là ước của 24: tất cả!
```

####  *D. Tấn Công 2: Index of Coincidence**

**Định nghĩa:**
```
IC = Σᵢ nᵢ(nᵢ-1) / (N(N-1))

Trong đó:
- nᵢ = số lần ký tự i xuất hiện
- N = tổng số ký tự
```

**Giá trị típ:**
```
Tiếng Anh: IC ≈ 0.065
Random: IC ≈ 0.038
```

**Phương pháp:**
```
1. Thử m = 1, 2, 3, ..., 20
2. Với mỗi m, tách thành m "cột"
3. Tính IC của mỗi cột
4. Nếu IC ≈ 0.065 → m đúng
```

####  **E. Hàm Thực Hiện**

```python
def vigenere_encrypt(plaintext, key):
    """Mã hóa Vigenère"""
    ciphertext = ""
    key_upper = key.upper()
    key_idx = 0
    
    for char in plaintext:
        if char.isalpha():
            shift = ord(key_upper[key_idx % len(key)]) - ord('A')
            if char.isupper():
                encrypted = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            ciphertext += encrypted
            key_idx += 1
        else:
            ciphertext += char
    
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    """Giải mã Vigenère"""
    plaintext = ""
    key_upper = key.upper()
    key_idx = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key_upper[key_idx % len(key)]) - ord('A')
            if char.isupper():
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            plaintext += decrypted
            key_idx += 1
        else:
            plaintext += char
    
    return plaintext

def kasiski_examination(ciphertext):
    """
    Kasiski examination để tìm độ dài khóa
    Tìm trigrams lặp lại và tính GCD
    """
    trigrams = {}
    for i in range(len(ciphertext) - 2):
        tri = ciphertext[i:i+3]
        if tri not in trigrams:
            trigrams[tri] = []
        trigrams[tri].append(i)
    
    distances = []
    for tri, positions in trigrams.items():
        if len(positions) > 1:
            for i in range(len(positions) - 1):
                distances.append(positions[i+1] - positions[i])
    
    if not distances:
        return None
    
    from math import gcd
    from functools import reduce
    key_length = reduce(gcd, distances)
    
    return key_length if key_length > 1 else None

def index_of_coincidence(text):
    """Tính Index of Coincidence"""
    freq = {}
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    
    n = sum(freq.values())
    if n < 2:
        return 0
    
    ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
    return ic
```

**Độ phức tạp tấn công:** O(n²) nếu biết độ dài khóa

**Kết quả thực nghiệm:**
![Kết quả 11](/home/lenovo/cryptography_project/results/test3.3.png)

### 3.4 Hill Cipher - Matrix Cipher

####  **A. Lý Thuyết**

**Định nghĩa:**
```
Mã hóa: C ≡ K × P (mod 26)
Giải mã: P ≡ K⁻¹ × C (mod 26)

Trong đó:
- K: ma trận khóa 2×2 hoặc 3×3
- P: vector plaintext
- C: vector ciphertext
```

**Điều kiện:**
```
gcd(det(K), 26) = 1
(ma trận phải khả nghịch mod 26)
```

####  **B. Ví Dụ 2×2**

```
Khóa: K = [1 2]
          [3 5]

det(K) = 1×5 - 2×3 = -1 ≡ 25 (mod 26)
gcd(25, 26) = 1 ✓ (khả nghịch)

Mã hóa "HE":
H = 7, E = 4
P = [7, 4]ᵀ

C ≡ [1 2] × [7] ≡ [1×7 + 2×4] ≡ [15] (mod 26)
    [3 5]   [4]   [3×7 + 5×4]   [41]

C ≡ [15, 15] (mod 26) → "PP"

Giải mã "PP":
K⁻¹ ≡ (det⁻¹) × [5 -2] ≡ 25 × [5 -2] ≡ [125 -50] ≡ [21 24] (mod 26)
                [-3 1]        [-3 1]     [-75  25]    [3  25]

P ≡ [21 24] × [15] ≡ [21×15 + 24×15] ≡ [525] ≡ [7] (mod 26) → "HE" ✓
    [3  25]   [15]   [3×15 + 25×15]    [420]   [4]
```

####  **C. Hàm Thực Hiện**

```python
def hill_cipher_encrypt_2x2(plaintext, key_matrix):
    """
    Mã hóa Hill cipher 2x2
    key_matrix: [[a, b], [c, d]]
    """
    P_vec = [ord(c) - ord('A') for c in plaintext if c.isalpha()]
    
    ciphertext = ""
    for i in range(0, len(P_vec) - 1, 2):
        P = [[P_vec[i]], [P_vec[i+1]]]
        C = matrix_multiply(key_matrix, P, 26)
        ciphertext += chr(C[0][0] + ord('A')) + chr(C[1][0] + ord('A'))
    
    return ciphertext

def hill_cipher_decrypt_2x2(ciphertext, key_matrix_inv):
    """Giải mã Hill cipher 2x2"""
    C_vec = [ord(c) - ord('A') for c in ciphertext if c.isalpha()]
    
    plaintext = ""
    for i in range(0, len(C_vec) - 1, 2):
        C = [[C_vec[i]], [C_vec[i+1]]]
        P = matrix_multiply(key_matrix_inv, C, 26)
        plaintext += chr(P[0][0] + ord('A')) + chr(P[1][0] + ord('A'))
    
    return plaintext
```

**Độ phức tạp:** O(n × k³) với k là kích thước ma trận

**Kết quả thực nghiệm:**
![Kết quả 12](/home/lenovo/cryptography_project/results/test3.4.png)

### 3.5 Playfair Cipher

####  **A. Lý Thuyết**

**Đặc điểm:**
- Mã hóa từng cặp ký tự (digraph)
- Dùng ma trận 5×5 (25 ký tự, J = I)
- Quy tắc: 
  - Cùng hàng: dịch sang phải (circular)
  - Cùng cột: dịch xuống (circular)
  - Hình chữ nhật: swap 2 góc ngang

####  **B. Ví Dụ**

```
Key: PLAYFAIR
Bảng:
P L A Y F
I R E X M
B C D G H
K N O S T
U V W Z Q

Mã hóa "HELLO":
HE: H(2,3), E(1,2) - hình chữ nhật → X(1,3), G(2,2) = XG
LL: L(0,1), L(0,1) - cùng ký tự → thêm X → LL = LX LL
O: cuối → X

Ciphertext: XGLXLX
```

####  **C. Hàm Thực Hiện**

```python
def playfair_create_key_matrix(key):
    """Tạo bảng Playfair 5x5"""
    key = key.upper().replace('J', 'I')
    used = set()
    matrix = []
    
    # Thêm ký tự từ key
    for char in key:
        if char.isalpha() and char not in used:
            matrix.append(char)
            used.add(char)
    
    # Thêm các ký tự còn lại
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used:
            matrix.append(char)
            used.add(char)
    
    return [matrix[i*5:(i+1)*5] for i in range(5)]

def playfair_find_char(matrix, char):
    """Tìm vị trí ký tự"""
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None

def playfair_encrypt(plaintext, key):
    """Mã hóa Playfair"""
    matrix = playfair_create_key_matrix(key)
    plaintext = plaintext.upper().replace('J', 'I')
    plaintext = ''.join(c for c in plaintext if c.isalpha())
    
    # Xử lý cặp ký tự trùng
    processed = ""
    i = 0
    while i < len(plaintext):
        if i + 1 < len(plaintext) and plaintext[i] == plaintext[i+1]:
            processed += plaintext[i] + 'X'
            i += 1
        else:
            processed += plaintext[i:i+2]
            i += 2
    
    if len(processed) % 2 == 1:
        processed += 'X'
    
    ciphertext = ""
    for i in range(0, len(processed), 2):
        c1, c2 = processed[i], processed[i+1]
        r1, col1 = playfair_find_char(matrix, c1)
        r2, col2 = playfair_find_char(matrix, c2)
        
        if r1 == r2:  # Cùng hàng
            ciphertext += matrix[r1][(col1 + 1) % 5] + matrix[r2][(col2 + 1) % 5]
        elif col1 == col2:  # Cùng cột
            ciphertext += matrix[(r1 + 1) % 5][col1] + matrix[(r2 + 1) % 5][col2]
        else:  # Hình chữ nhật
            ciphertext += matrix[r1][col2] + matrix[r2][col1]
    
    return ciphertext
```

**Kết quả thực nghiệm:**
![Kết quả 13](/home/lenovo/cryptography_project/results/test3.5.png)

### 3.6 Rabin Cipher - Quadratic Residue

####  **A. Lý Thuyết**

**Định nghĩa:**
```
Mã hóa: C ≡ M² (mod n)
Giải mã: M ≡ √C (mod n)

Trong đó:
- n = p × q (hai số nguyên tố)
- M < √n
```

**Đặc điểm:**
- Dễ mã hóa: bình phương 1 phép
- Khó giải mã: tìm căn bậc 2 mod n
- Chứng minh được an toàn như factorization
- Có 4 căn bậc 2 mod n (ambiguity)

####  **B. Ví Dụ**

```
p = 61, q = 53
n = 61 × 53 = 3233

Mã hóa M = 65:
C ≡ 65² ≡ 4225 ≡ 992 (mod 3233)

Giải mã (cần biết p, q):
Giải 2 phương trình:
  M² ≡ 992 (mod 61)
  M² ≡ 992 (mod 53)

Dùng CRT kết hợp → 4 nghiệm có thể
```

####  **C. Hàm Thực Hiện**

```python
def rabin_encrypt(m, n):
    """Mã hóa Rabin: C = M² mod n"""
    return (m * m) % n

def rabin_decrypt(c, p, q):
    """
    Giải mã Rabin
    Cần biết p, q để tính căn bậc 2
    """
    n = p * q
    
    # Giải M² ≡ c (mod p) và M² ≡ c (mod q)
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    
    # Dùng CRT để kết hợp
    # Tính y sao cho y ≡ 1 (mod p) và y ≡ 0 (mod q)
    yp = pow(q, -1, p)
    yq = pow(p, -1, q)
    
    r1 = (mp * q * yp + mq * p * yq) % n
    r2 = n - r1
    r3 = (mp * q * yp - mq * p * yq) % n
    r4 = n - r3
    
    return [r1, r2, r3, r4]
```
**Kết quả thực nghiệm:**
![Kết quả 14](/home/lenovo/cryptography_project/results/test3.6.png)

### So Sánh Các Mã Cổ Điển

| Loại | Khóa | Bảo Mật | Tấn Công | Tốc độ |
|------|------|---------|----------|-------|
| **Caesar** | 26 | ✗ Rất yếu | Brute force O(26n) | Cực nhanh |
| **Substitution** | 26! | ✗ Yếu | Frequency O(n) | Cực nhanh |
| **Vigenère** | m × 26^m | ⚠ Yếu | Kasiski + IC | Cực nhanh |
| **Hill** | (26!)^k² | ⚠ Yếu | Known plaintext | Nhanh |
| **Playfair** | 25! | ⚠ Yếu | Digraph frequency | Nhanh |
| **Rabin** | n = pq | ⚠ Thường | Factorization | Chậm |

---

## CHƯƠNG 4: MÃ KHÓA ĐỐI XỨNG HIỆN ĐẠI

### Giới tiệu

Mã khối đối xứng hiện đại xây dựng trên các nguyên tắc:
- **Confusion (Nhầm lẫn):** Quan hệ phức tạp giữa plaintext, ciphertext, và key
- **Diffusion (Khuếch tán):** Thay đổi 1 bit plaintext → ảnh hưởng nhiều bits ciphertext
- **Mạng Feistel:** Kết hợp cả 2 nguyên tắc trên

### 4.1 & 4.2 Sơ đồ khối hệ mật

**Cấu trúc chung:**
```
Plaintext (64/128/256 bits)
    ↓
[Initial Permutation (IP)]
    ↓
[16/32 Vòng Feistel]
  - Mỗi vòng: S-boxes + P-boxes + XOR với key
    ↓
[Final Permutation (IP^-1)]
    ↓
Ciphertext (64/128/256 bits)
```

**Các bước chính:**
1. **Key Schedule:** Sinh khóa vòng từ master key
2. **Initial Permutation:** Hoán vị ban đầu
3. **Round Function:** Lặp lại với mỗi khóa vòng
4. **Final Permutation:** Hoán vị cuối cùng

### 4.3 Mã Khối & Chuyển Vị

**Mã khối (Block Cipher):**
- Chia dữ liệu thành các khối cố định
- Mã hóa từng khối độc lập
- DES: 64-bit blocks
- AES: 128-bit blocks

**Chuyển Vị (Permutation):**
```
Ví dụ 8-bit permutation:
Input:  10110010 (vị trí 1 2 3 4 5 6 7 8)
Table:  [8 6 4 2 7 5 3 1]
Output: 01011001

Giải thích: 
Output[0] = Input[8-1] = Input[7] = 0
Output[1] = Input[6-1] = Input[5] = 1
Output[2] = Input[4-1] = Input[3] = 0
...
```

### 4.4 P-box (Permutation Box)

####  **A. Định Nghĩa**

**P-box:** Chỉ thực hiện hoán vị các bits, không thay đổi giá trị

**Công thức:**
```
Output[i] = Input[Permutation_table[i]]
```

####  **B. 3 Loại P-box**

**1. Straight P-box (Hoán vị thẳng):**
```
Kích thước input = Kích thước output = n
Mỗi bit input được hoán vị đến 1 vị trí output

Ví dụ 8-bit:
Input:  b₁ b₂ b₃ b₄ b₅ b₆ b₇ b₈
Table:  [8 6 4 2 7 5 3 1]
Output: b₈ b₆ b₄ b₂ b₇ b₅ b₃ b₁
```

**2. Expansion P-box (Mở rộng):**
```
Kích thước output > Kích thước input
Một số bits được lặp lại

DES Expansion (32 → 48 bits):
Input:  32 bits
Output: 48 bits (một số bits được dùng 2 lần)

Ví dụ:
Table: [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, ...]
       (bit 4 và 5 xuất hiện 2 lần)
```

**3. Compression P-box (Nén):**
```
Kích thước output < Kích thước input
Bỏ đi một số bits

DES Compression (56 → 48 bits):
Input:  56 bits
Output: 48 bits (8 bits bị loại bỏ)
```

####  **C. Hàm Thực Hiện**

```python
def permutation_box(input_bits, permutation_table):
    """
    P-box (Permutation box)
    
    Tham số:
    - input_bits: Số nguyên (các bits đầu vào)
    - permutation_table: Danh sách các vị trí (1-indexed)
    
    Ví dụ:
    input_bits = 0b10110010
    perm_table = [8, 6, 4, 2, 7, 5, 3, 1]
    Output bit 0 = Input bit 7 (8-1)
    """
    output = 0
    for i, perm_idx in enumerate(permutation_table):
        if (input_bits >> (perm_idx - 1)) & 1:
            output |= (1 << (len(permutation_table) - 1 - i))
    return output

def expansion_box(input_bits, expansion_table):
    """
    Expansion P-box: Mở rộng 32 → 48 bits (DES)
    Một số bits được lặp lại
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
```

####  **D. Ví Dụ Chi Tiết**

```
Straight P-box 8-bit:
Input:  10110010 (0xB2)
Table:  [8, 6, 4, 2, 7, 5, 3, 1]

Tính toán:
Output[0] = Input[8-1] = Input[7] = 0
Output[1] = Input[6-1] = Input[5] = 1
Output[2] = Input[4-1] = Input[3] = 0
Output[3] = Input[2-1] = Input[1] = 1
Output[4] = Input[7-1] = Input[6] = 1
Output[5] = Input[5-1] = Input[4] = 1
Output[6] = Input[3-1] = Input[2] = 0
Output[7] = Input[1-1] = Input[0] = 1

Output: 01011101 (0x5D) ✓
```
**Kết quả thực nghiệm:**
![Kết quả 15](/home/lenovo/cryptography_project/results/test4.1.png)

### 4.5 S-box (Substitution Box)

####  **A. Định Nghĩa**

**S-box:** Bảng lookup (LUT) thực hiện thay thế (substitution)
- Không phải xor hoặc AND/OR
- Cung cấp **tính phi tuyến** (nonlinearity)
- Mỗi đầu vào → đầu ra duy nhất

####  **B. Cấu Trúc**

**DES S-boxes:**
```
8 S-boxes (S1 đến S8)
Mỗi box: 6 bits input → 4 bits output
Bảng: 4 hàng × 16 cột = 64 phần tử

Row index = bit 0 + bit 5 (2 bit ngoài)
Col index = bits 1-4 (4 bit trong)
```

**AES S-box (Rijndael):**
```
1 S-box
8 bits input → 8 bits output
Bảng: 16 × 16 = 256 phần tử

Tính toán: 
1. Tìm phần tử nghịch đảo trong GF(2^8)
2. Áp dụng biến đổi affine
```

####  **C. Hàm Thực Hiện**

```python
# DES S1 box
DES_S1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 0, 5],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

def substitution_box(input_6bits, sbox):
    """
    S-box: 6 bits → 4 bits
    
    Ví dụ DES S1:
    Input: 011011 (27)
    Row = bit 0 + (bit 5 << 1) = 1 + 0 = 1
    Col = bits 1-4 = 1101 = 13
    Output = sbox[1][13] = 1
    """
    row = ((input_6bits >> 5) & 1) | (((input_6bits) & 1) << 1)
    col = (input_6bits >> 1) & 0xF
    return sbox[row][col]
```

####  **D. Ví Dụ Chi Tiết**

```
DES S1 box, Input: 011011 (6 bits)

Bước 1: Tìm row
  Bit 0 (ngoài cùng phải) = 1
  Bit 5 (ngoài cùng trái) = 0
  Row = 0 | (1 << 1) = 2

Bước 2: Tìm col
  Bits 1-4 (giữa) = 1101 = 13
  Col = 13

Bước 3: Tra cứu bảng
  DES_S1[2][13] = 0

Output: 0000 (4 bits) ✓
```

### 4.6 Feistel Network

####  **A. Lý Thuyết**

**Cấu trúc Feistel:**
```
Vòng i:
  L_{i+1} = R_i
  R_{i+1} = L_i ⊕ f(R_i, K_i)

Trong đó:
- L_i, R_i: Nửa trái/phải
- f(): Hàm vòng (round function)
- K_i: Khóa vòng
- ⊕: XOR
```

**Ưu điểm:**
1. **Đảm bảo invertibility:** Dễ giải mã
2. **Hàm f không cần khả nghịch:** Không phải hàm một-một
3. **Cùng cấu trúc cho encrypt/decrypt:** Chỉ đảo ngược thứ tự khóa

####  **B. Hàm Vòng f()**

**Thành phần:**
```
f(R, K) = [P-box(S-boxes(expansion(R) ⊕ K))]

Bước:
1. Expansion: 32 → 48 bits (lặp lại bit)
2. XOR với K: 48 ⊕ 48
3. S-boxes: 48 → 32 bits (8 S-boxes 6→4)
4. P-box: Hoán vị 32 bits
```

####  **C. Hàm Thực Hiện**

```python
def feistel_round(left, right, round_key, sbox_tables=None, pbox_table=None):
    """
    Một vòng Feistel
    
    Công thức:
    L' = R
    R' = L XOR f(R, K)
    """
    # Round function (đơn giản)
    f_output = right ^ round_key
    
    # Nếu có S-boxes
    if sbox_tables:
        # Chia thành 8 khối 6-bit và thay thế
        substituted = 0
        for i in range(8):
            input_6bits = (f_output >> (42 - 6*i)) & 0x3F
            output_4bits = substitution_box(input_6bits, sbox_tables[i])
            substituted |= (output_4bits << (28 - 4*i))
        f_output = substituted
    
    new_left = right
    new_right = left ^ f_output
    
    return new_left, new_right

def feistel_encrypt(plaintext, keys, rounds=16):
    """
    Mã hóa Feistel (ví dụ DES)
    
    plaintext: 64 bits
    keys: Danh sách khóa vòng (16 khóa)
    rounds: Số vòng (DES = 16)
    """
    # Chia plaintext thành 2 nửa 32-bit
    left = plaintext >> 32
    right = plaintext & 0xFFFFFFFF
    
    # 16 vòng Feistel
    for i in range(rounds):
        left, right = feistel_round(left, right, keys[i])
    
    # Hoán đổi cuối cùng (swap)
    left, right = right, left
    
    # Kết hợp 2 nửa
    ciphertext = (left << 32) | right
    return ciphertext

def feistel_decrypt(ciphertext, keys, rounds=16):
    """
    Giải mã Feistel (sử dụng keys theo thứ tự ngược)
    
    Chỉ cần đảo ngược thứ tự khóa vòng
    """
    return feistel_encrypt(ciphertext, keys[::-1], rounds)
```

####  **D. Ví Dụ Chi Tiết**

```
Vòng 1 của Feistel:
L₀ = 0x12345678
R₀ = 0x9ABCDEF0
K₁ = 0xF00DBEEF

Tính toán:
1. f(R₀, K₁) = f(0x9ABCDEF0, 0xF00DBEEF)
   - Expansion: 32 → 48 bits
   - XOR: 48 ⊕ 48
   - S-boxes: 48 → 32 bits
   - P-box: Hoán vị
   - f_output = 0x12345678 (ví dụ)

2. L₁ = R₀ = 0x9ABCDEF0
   R₁ = L₀ ⊕ f_output = 0x12345678 ⊕ 0x12345678 = 0x00000000

Sau vòng 1:
L₁ = 0x9ABCDEF0
R₁ = 0x00000000
```

**Kết quả thực nghiệm:**
![Kết quả 16](/home/lenovo/cryptography_project/results/test4.2.png)

### 4.7 Kết Hợp P-box & S-box & Feistel

####  **A. Cấu Trúc DES (Data Encryption Standard)**

```
DES (64-bit plaintext, 56-bit key):

1. Initial Permutation (IP): 64 → 64 bits (hoán vị)
2. 16 vòng Feistel:
   - Mỗi vòng:
     a. Expansion: 32 → 48 bits
     b. XOR với K_i: 48 ⊕ 48
     c. S-boxes: 48 → 32 bits (8 S-boxes 6→4)
     d. P-box: Hoán vị 32 bits
     e. XOR với L_i
3. Final Permutation (IP^-1): 64 → 64 bits
```

####  **B. Confusion & Diffusion**

**Confusion (S-boxes):**
```
- Thay đổi phi tuyến các bits
- Mỗi output bit phụ thuộc vào nhiều input bits
- Khiến key khó được xác định từ plaintext/ciphertext
```

**Diffusion (P-boxes & Feistel):**
```
- Hoán vị các bits
- Thay đổi 1 bit plaintext → ảnh hưởng nhiều bits ciphertext
- Sau n vòng: 1 bit thay đổi → ~n×2 bits output thay đổi (avalanche effect)
```

####  **C. Hàm Thực Hiện**

```python
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
            round_key = (
                (master_key << (i + 1)) | 
                (master_key >> (self.key_size - i - 1))
            ) & ((1 << self.key_size) - 1)
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
```

**Kết quả thực nghiệm:**
![Kết quả 17](/home/lenovo/cryptography_project/results/test4.345.png)

### Tính Chất Bảo Mật

| Tính Chất | Phần Tử | Mục Đích |
|-----------|---------|----------|
| **Confusion** | S-boxes | Thay đổi phi tuyến |
| **Diffusion** | P-boxes + Feistel | Hoán vị & khuếch tán |
| **Invertibility** | Feistel structure | Dễ giải mã |
| **Avalanche Effect** | Nhiều vòng | 1 bit → nhiều bits thay đổi |

---

## CHƯƠNG 5: MÃ DES (DATA ENCRYPTION STANDARD)

### Giới Thiệu

DES (Data Encryption Standard) được phát hành năm 1977, dựa trên Feistel Network với:
- Khóa: 56-bit (+ 8 bits parity = 64-bit input)
- Khối: 64-bit
- Vòng: 16 vòng Feistel
- S-boxes: 8 cái (6→4 bits)
- P-boxes: Hoán vị bits

### 5.1 Cấu Trúc DES

####  **A. Sơ Đồ Khối Tổng Quát**

```
INPUT (64-bit plaintext)
    ↓
[Initial Permutation (IP)]
    ↓
[Split into L₀, R₀] (mỗi 32-bit)
    ↓
[16 vòng Feistel]
    ↓
[Final Swap: R₁₆ || L₁₆]
    ↓
[Final Permutation (IP⁻¹)]
    ↓
OUTPUT (64-bit ciphertext)
```

####  **B. Hàm Feistel f(R, K)**

**Công thức:**
```
f(R, K) = P-box(S-boxes(E(R) ⊕ K))

Bước chi tiết:
1. Expansion: E(R)   [32 → 48 bits]
2. XOR với K: E(R) ⊕ K   [48 bits]
3. S-box sub: S₁...S₈    [48 → 32 bits]
4. P-box perm: P         [32 → 32 bits]
```

####  **C. Key Schedule**

**Bước 1: Permuted Choice 1 (PC-1)**
```
Input: 64-bit key (với 8 parity bits ở vị trí 8, 16, 24, 32, 40, 48, 56, 64)
Output: 56-bit key (loại bỏ parity bits)
Split: C₀ (28-bit), D₀ (28-bit)
```

**Bước 2: Key Schedule Loop**
```
For i = 1 to 16:
  - Left shift: Cᵢ = LS(Cᵢ₋₁), Dᵢ = LS(Dᵢ₋₁)
    (Shift 1 bit nếu i ∈ {1, 2, 9, 16}; shift 2 bits khác)
  - Kᵢ = PC-2(Cᵢ || Dᵢ)  [56 → 48 bits]
```

####  **D. Ví Dụ Chi Tiết**

```
Plaintext: 0x0123456789ABCDEF (64 bits)
Key:       0x133457799BBCDFF1 (64 bits, với parity)

Bước 1: Initial Permutation (IP)
  Input:  0x0123456789ABCDEF
  Output: L₀ = 0xCC00CCFF
          R₀ = 0xF0AAF0AA

Bước 2: Vòng 1
  K₁ = 0x1B02468ACE (48 bits từ key schedule)
  f(R₀, K₁) = ... = 0xF0XX_XXXX
  L₁ = R₀ = 0xF0AAF0AA
  R₁ = L₀ ⊕ f(R₀, K₁) = 0xCC00CCFF ⊕ f(R₀, K₁) = 0x3C56_9C55

Bước 3: Vòng 2-16: Lặp lại với K₂...K₁₆

Bước 4: Final Swap & Final Permutation (IP⁻¹)
  Output: 0x85E813540F0AB405
```

### 5.2 Điểm Yếu của DES

####  **1. Kích Thước Khóa Nhỏ: 56 bits**

**Không gian khóa:**
```
2^56 ≈ 7.2 × 10^16 khóa có thể

Timeline tấn công:
1977: DES được chuẩn hóa (đủ an toàn)
1998: EFF Deep Crack - tìm khóa trong 56 giờ
2024: GPU brute force - vài giờ
```

**Ứng dụng:**
```
Ví dụ mã hóa tất cả khóa 56-bit:
- Thử 10^15 khóa/giây
- Cần ~7200 giây = 2 giờ
```

#### **2. Kích Thước Khối Nhỏ: 64 bits**

**Birthday Attack:**
```
Tính chất: Sau √(2^64) = 2^32 khối (~4 tỷ khối), 
           xác suất collision > 50%

Ứng dụng: ~16 EB dữ liệu → nguy hiểm!
```

#### **3. Weak Keys**

```
4 weak keys (encryption = decryption):
- 0x0101010101010101
- 0xFEFEFEFEFEFEFEFE
- 0xE0E0E0E0F1F1F1F1
- 0x1F1F1F1F0E0E0E0E

Nguyên nhân: Key schedule sinh K₁ = K₂ = ... = K₁₆
```

### 5.3 Triple DES (3DES)

#### **A. Định Nghĩa**

**3DES (EDE mode - Encrypt-Decrypt-Encrypt):**
```
Ciphertext = E(D(E(Plaintext, K₁), K₂), K₃)

Nếu K₁ = K₃ (2-key 3DES):
Ciphertext = E(D(E(P, K₁), K₂), K₁)
Kích thước khóa: ~112 bits
```

#### **B. Ví Dụ**

```
Plaintext: 0x0123456789ABCDEF
K₁ = 0x0123456789ABCDEF
K₂ = 0xFEDCBA9876543210
K₃ = K₁

Step 1: T₁ = E(P, K₁)  = 0x85E813540F0AB405
Step 2: T₂ = D(T₁, K₂) = 0x... (giải mã với K₂)
Step 3: C = E(T₂, K₃)  = 0x... (mã hóa lại với K₃)

Output: Ciphertext
```

####  **C. So Sánh DES vs 3DES**

| Tiêu chí | DES | 3DES |
|----------|-----|------|
| Khóa | 56-bit | 168-bit (2-key: 112-bit) |
| Khối | 64-bit | 64-bit |
| Vòng | 16 | 48 (3×16) |
| Tốc độ | Nhanh | 1/3 DES |
| Bảo mật | ✗ Lỗi thời | ⚠ Legacy (dần thay AES) |

### 5.4 Tấn Công Meet-in-the-Middle lên 2DES

####  **Khái Niệm**

```
2DES: C = E(E(P, K₁), K₂)

Thay vì thử 2^112 khóa, tấn công M-i-M:
1. Tính E(P, K₁) với tất cả 2^56 khóa K₁
   → Lưu vào bảng hash H

2. Tính D(C, K₂) với tất cả 2^56 khóa K₂
   → Tìm trong bảng H

3. Nếu tìm thấy: (K₁*, K₂*) là khóa đúng!

Phức tạp: 2^56 + 2^56 = 2^57 (chỉ tốn 1 bit!)
```

####  **Ví Dụ**

```
P = 0x0123456789ABCDEF
K₁ = 0x0123456789ABCDEF
K₂ = 0xFEDCBA9876543210
C = E(E(P, K₁), K₂) = 0x85E813540F0AB405

Tấn công:
1. Tính T = E(P, K₁) cho tất cả K₁:
   K₁ = 0x0123456789ABCDEF → T = 0x85E813540F0AB405
   ...

2. Tính D(C, K₂) cho tất cả K₂:
   K₂ = 0xFEDCBA9876543210 → D(C, K₂) = 0x85E813540F0AB405
   ...

3. Match! → (K₁, K₂) tìm được
```

### Kết Quả Kiểm Thử
**Kết quả thực nghiệm:**
![Kết quả 18](/home/lenovo/cryptography_project/results/test6-des.png)
![Kết quả 19](/home/lenovo/cryptography_project/results/test6-des2.png)

### 5.5 Cơ Chế Hoạt Động Chi Tiết

####  **A. S-box DES S1 (Ví dụ)**

```
Input: 6 bits = 011011 (row 2, col 13)
Output: DES_S1[2][13] = 5 (4 bits = 0101)

Lợi ích: Phi tuyến hóa, chống frequency analysis
```

####  **B. Initial & Final Permutation**

```
IP (Initial Permutation):
Nhằm mục đích (theo Coppersmith):
- Vị trí của bits phát huy tác dụng với S-boxes đầu tiên
- Làm cho bit 1 của plaintext ảnh hưởng đến S-box 1

IP⁻¹ (Final Permutation):
- Đảo ngược của IP
- Không ảnh hưởng đến bảo mật (chỉ là hoán vị)
```

### Kết Luận

**DES:**
- ✓ Có lịch sử quan trọng (công cụ mật mã đầu tiên được tiêu chuẩn hóa)
- ✓ Cấu trúc Feistel rất đẹp (dễ hiểu, dễ phân tích)
- ✗ Khóa quá nhỏ (56-bit) → Lỗi thời
- ✗ Khối quá nhỏ (64-bit) → Nguy hiểm với dữ liệu lớn

**3DES:**
- ⚠ Cải thiện (112-168 bit khóa)
- ⚠ Còn sử dụng (legacy systems)
- ✗ Chậm (3x DES)
- → **Nên thay bằng AES**

**Mật mã hiện đại hơn:**
- **Hiện đại:** AES-128, AES-256
- **Tương lai:** ChaCha20 hoặc tiêu chuẩn mới

**File code:** `Chuong5_MaDES/DES.py`

---

## CHƯƠNG 6: MÃ AES (ADVANCED ENCRYPTION STANDARD)

### Giới Thiệu

AES (Advanced Encryption Standard) được phát hành năm 2001, thay thế DES:
- Khóa: 128/192/256-bit
- Khối: 128-bit (cố định)
- Vòng: 10/12/14 (phụ thuộc khóa)
- Cấu trúc: SPN (Substitution-Permutation Network) chứ không phải Feistel
- S-boxes: 1 cái (8→8 bits, dựa trên GF(2^8))

### 6.1 So Sánh DES vs AES

| Tiêu chí | DES | AES |
|----------|-----|-----|
| **Khóa** | 56-bit | 128/192/256-bit |
| **Khối** | 64-bit | 128-bit (cố định) |
| **Vòng** | 16 | 10/12/14 |
| **Cấu trúc** | Feistel | SPN (Substitution-Permutation) |
| **S-box** | 8 × (6→4 bits) | 1 × (8→8 bits) |
| **Tốc độ** | Chập | Nhanh (~3-5x DES) |
| **Bảo mật** | ✗ Lỗi thời | ✓ Hiện đại |

### 6.2 Các Phép Biến Đổi AES

####  **A. SubBytes (S-box Substitution)**

**Công thức (trong GF(2^8)):**
```
S(x) = M × x^(-1) + c

Trong đó:
- x^(-1): Nghịch đảo nhân trong GF(2^8)
  (GF(2^8) xác định bởi đa thức tối giản p(x) = x^8 + x^4 + x^3 + x + 1)
- M: Ma trận 8×8 affine transformation
- c: Hằng số 0x63
```

**Ví Dụ Chi Tiết:**
```
Input: 0x53 (ký tự 'S')

Bước 1: Tính 0x53^(-1) trong GF(2^8)
  0x53 = 01010011
  (Dùng extended GCD hoặc lookup table)
  0x53^(-1) = 0xCA

Bước 2: Áp dụng affine transformation
  [0xCA] × [matrix M] + 0x63 (mod 2)
  = 0xED

Output: 0xED
```

**Tính Chất:**
- ✓ Phi tuyến (chống linear cryptanalysis)
- ✓ Tối đa độ chênh lệch (chống differential cryptanalysis)
- ✓ Bảng S-box chuẩn (không có backdoor)
- ✓ Có inverse S-box để giải mã

**Bảng S-box AES (16×16, chứa tất cả 256 giá trị):**
```
   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
0: 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
1: CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
...
```

####  **B. ShiftRows (Hàng Dịch)**

**Công Thức:**
```
State (4×4 matrix):
Row 0: không dịch
Row 1: dịch trái 1 byte
Row 2: dịch trái 2 bytes
Row 3: dịch trái 3 bytes
```

**Ví Dụ Chi Tiết:**
```
Trước ShiftRows:
[S00  S04  S08  S0C]     [00  04  08  0C]
[S10  S14  S18  S1C]  =  [01  05  09  0D]
[S20  S24  S28  S2C]     [02  06  0A  0E]
[S30  S34  S38  S3C]     [03  07  0B  0F]

Sau ShiftRows:
[S00  S04  S08  S0C]     [00  04  08  0C]
[S14  S18  S1C  S10]  =  [05  09  0D  01]  (dịch 1 byte)
[S28  S2C  S20  S24]     [0A  0E  02  06]  (dịch 2 bytes)
[S3C  S30  S34  S38]     [0F  03  07  0B]  (dịch 3 bytes)
```

**Mục Đích:**
- ✓ Tạo diffusion: Thay đổi 1 byte → Ảnh hưởng nhiều byte ở vòng sau
- ✓ Kết hợp với SubBytes để tạo confusion + diffusion


####  **C. MixColumns (Trộn Cột)**

**Công Thức (trong GF(2^8)):**
```
[s'₀,ⱼ]   [02 03 01 01] [s₀,ⱼ]
[s'₁,ⱼ] = [01 02 03 01] [s₁,ⱼ]  (⊗ trong GF(2^8))
[s'₂,ⱼ]   [01 01 02 03] [s₂,ⱼ]
[s'₃,ⱼ]   [03 01 01 02] [s₃,ⱼ]

Trong GF(2^8), các phép toán khác với số thực:
- ⊕ là XOR (không phải cộng)
- ⊗ là phép nhân Galois (không phải nhân thường)
```

**Phép Nhân Galois:**
```
02 ⊗ 87:
  87 = 10000111
  Nhân với 2: 1 0000111 0 = 0001 1110 (shift trái)
  Nếu overflow (bit cao = 1): XOR với 0x1B (polynomial tối giản)
  10001110 XOR 00011011 = 10010101 = 0x95

03 ⊗ 87:
  03 = 02 + 01 (trong GF)
  03 ⊗ 87 = (02 ⊗ 87) ⊕ (01 ⊗ 87)
           = 0x95 ⊕ 0x87
           = 0x12
```

**Ví Dụ Chi Tiết (1 cột):**
```
Column: [87, 6E, 46, A6]ᵀ

s'₀ = (02⊗87) ⊕ (03⊗6E) ⊕ (01⊗46) ⊕ (01⊗A6)

Tính toán:
  02⊗87 = 0x95
  03⊗6E = 0x16
  01⊗46 = 0x46
  01⊗A6 = 0xA6
  
  s'₀ = 0x95 ⊕ 0x16 ⊕ 0x46 ⊕ 0xA6 = 0x47

(Tương tự cho s'₁, s'₂, s'₃)

Result: [47, XX, XX, XX]ᵀ
```

**Mục Đích:**
- ✓ Diffusion mạnh: 1 bit thay đổi → Ảnh hưởng 4 cột
- ✓ Kết hợp SubBytes + ShiftRows + MixColumns → Rất khó phân tích
- ✓ Bảo vệ chống differential & linear cryptanalysis


####  **D. AddRoundKey (XOR Khóa Vòng)**

**Công Thức:**
```
State ← State ⊕ RoundKey[round]

Các khóa vòng sinh từ master key bằng Key Schedule
```

**Ví Dụ:**
```
State (4 bytes): [00 01 02 03]
RoundKey:        [0F 0E 0D 0C]
Output:          [0F 0F 0F 0F]
```

### 6.3 Cấu Trúc AES Đầy Đủ

####  **A. Tổng Quan**

```
Plaintext (128-bit)
    ↓
[Initial AddRoundKey]
    ↓
[10/12/14 vòng]:
  1. SubBytes (S-box)
  2. ShiftRows (Permutation)
  3. MixColumns (Linear mixing) - Bỏ qua ở vòng cuối
  4. AddRoundKey (XOR khóa)
    ↓
Ciphertext (128-bit)
```

####  **B. Số Vòng**

| Kích Thước Khóa | Vòng |
|-----------------|------|
| 128-bit | 10 |
| 192-bit | 12 |
| 256-bit | 14 |

### 6.4 Key Schedule AES

####  **A. Sinh Khóa Vòng**

```
Từ master key (128/192/256-bit), sinh các khóa vòng cho mỗi vòng

Bước:
1. Chia key thành từ 32-bit (4 bytes)
2. Cho mỗi từ mới:
   - Rotate-word: [a0, a1, a2, a3] → [a1, a2, a3, a0]
   - SubWord: Áp dụng S-box trên mỗi byte
   - XOR với Rcon: [0x01, 0x00, 0x00, 0x00] × x^round (trong GF(2^8))
   - XOR với từ trước
```

####  **B. Ví Dụ**

```
Master Key (128-bit): 2B7E151628AED2A6ABF7158809CF4F3C

Word0 = 2B7E1516
Word1 = 28AED2A6
Word2 = ABCF7158
Word3 = 809CF4F3

Sinh Word4:
  TempWord = RotWord(Word3) = 9CF4F380
  TempWord = SubWord(9CF4F380) = 8A84EB01
  TempWord = 8A84EB01 ⊕ Rcon[1] = 8A84EB01 ⊕ 01000000 = 8B84EB01
  Word4 = Word0 ⊕ TempWord = 2B7E1516 ⊕ 8B84EB01 = A0FA1654
```

### Kết Quả Kiểm Thử
**Kết quả thực nghiệm:**
![Kết quả 20](/home/lenovo/cryptography_project/results/test7-aes1.png)
![Kết quả 21](/home/lenovo/cryptography_project/results/test7-aes2.png)

### 6.5 Tấn Công AES

####  **1. Brute Force Khóa**

```
AES-128: 2^128 khóa → Không khả thi
AES-256: 2^256 khóa → càng không khả thi

Tính toán:
- Thử 10^18 khóa/giây (GPU hiện đại)
- AES-128: 2^128 / 10^18 ≈ 3.4 × 10^20 năm
- AES-256: ~5 × 10^60 năm
```

####  **2. Side-Channel Attacks**

```
- Timing attack: Phân tích thời gian thực thi
- Power analysis: Phân tích tiêu thụ năng lượng
- Cache timing: Phân tích cache hits/misses
- Phòng chống: Constant-time implementation
```

####  **3. Known-Plaintext Attack (KPA)**

```
Nếu biết nhiều (plaintext, ciphertext) pairs:
- Đối với AES: Vẫn cần 2^128 phép tính
- Kỹ thuật linear/differential cryptanalysis yếu hơn
```

####  *4. Padding Oracle Attack**

```
Nếu server tiết lộ thông tin padding:
- Có thể decrypt ciphertext từng byte
- Phòng chống: Authenticated encryption (AES-GCM)
```

### 6.6 Cấu Trúc Hoạt Động Chi Tiết

####  **A. Một Vòng AES**

```
State input (4×4 bytes):
[00 04 08 0C]
[01 05 09 0D]
[02 06 0A 0E]
[03 07 0B 0F]

1. SubBytes (áp dụng S-box trên mỗi byte):
[63 C0 A5 3E]
[4D 7E C4 EF]
[27 F5 1E 86]
[5F 47 AC FE]

2. ShiftRows (dịch từng hàng):
[63 C0 A5 3E]
[7E C4 EF 4D]
[1E 86 27 F5]
[FE 5F 47 AC]

3. MixColumns (trộn cột):
[47 75 40 F1]
[62 5D E8 A7]
[2F B8 61 1E]
[4A 1E 8D 77]

4. AddRoundKey (XOR khóa vòng):
[4A 7C 5E 3C]
[3B 19 2F 98]
[52 7D C1 43]
[15 23 8E 4E]
```

### Kết Luận

**AES:**
- ✓ Khóa lớn (128/192/256-bit) → An toàn
- ✓ Khối cố định 128-bit → Tối ưu
- ✓ Vòng ít (10-14) → Nhanh
- ✓ Cấu trúc SPN → Dễ phân tích, khó phá vỡ
- ✓ Tiêu chuẩn toàn cầu → Được tin tưởng

**Khuyên dùng:**
- **Hiện nay:** AES-128 (đủ an toàn)
- **Dài hạn:** AES-256 (an toàn hơn)
- **Mục đích đặc biệt:** AES-GCM (authenticated encryption)

**File code:** `Chuong6_MaAES/AES.py`

---

## CHƯƠNG 7: MÃ RSA (RIVEST-SHAMIR-ADLEMAN)

### Giới Thiệu

RSA (1977) là hệ mã công khai dùng cho:
- **Mã hóa bất đối xứng:** Khóa công khai mã hóa, khóa riêng giải mã
- **Ký số (Digital Signature):** Ký với khóa riêng, xác minh với khóa công khai
- **Trao đổi khóa:** Mã hóa khóa đối xứng bằng RSA

Độ an toàn dựa trên: **Khó phân tích số lớn (Factorization Problem)**

### 7.1 Sinh Khóa RSA

#### **A. Bước 1: Chọn Hai Số Nguyên Tố p, q**

**Yêu Cầu:**
```
- p, q là số nguyên tố lớn (1024+ bits cho RSA-2048)
- p ≠ q
- |p - q| không quá gần (chống Fermat's factorization)
- (p-1) và (q-1) không có nhân tử nhỏ (chống P-1 attack)
- p, q độc lập và ngẫu nhiên
```

**Ví Dụ (Số Nhỏ):**
```
p = 61
q = 53

Kiểm tra:
- Cả 61 và 53 đều là số nguyên tố ✓
- |61 - 53| = 8 (không quá gần) ✓
- p-1 = 60 = 2^2 × 3 × 5
- q-1 = 52 = 2^2 × 13
```

#### **B. Bước 2: Tính n và φ(n)**

**Công Thức:**
```
n = p × q
φ(n) = (p-1) × (q-1)

(φ(n) là hàm Euler, số nguyên nhỏ hơn n và nguyên tố cùng n)
```

**Ví Dụ:**
```
n = 61 × 53 = 3233
φ(n) = 60 × 52 = 3120
```

#### **C. Bước 3: Chọn Exponent Công Khai e**

**Yêu Cầu:**
```
- 1 < e < φ(n)
- gcd(e, φ(n)) = 1  (e nguyên tố cùng φ(n))
```

**Thường Dùng:**
```
e = 65537 (0x10001) = 2^16 + 1

Lý do:
- Số nguyên tố Fermat
- Có ít bit = 1 → Luỹ thừa nhanh (16 bit shift + cộng)
- Công khai được biết đến (không gây lộ thông tin)
- gcd(65537, φ(n)) = 1 với hầu hết n
```

**Ví Dụ:**
```
Thử e = 17:
- gcd(17, 3120) = 1 ✓
- 1 < 17 < 3120 ✓
→ e = 17 hợp lệ!
```

#### **D. Bước 4: Tính Private Exponent d**

**Công Thức:**
```
Tìm d sao cho: e × d ≡ 1 (mod φ(n))

Phương pháp: Extended Euclidean Algorithm
```

**Chi Tiết Tính Toán:**
```
Extended_GCD(e=17, φ(n)=3120):

17 × d ≡ 1 (mod 3120)
17 × d = 1 + k × 3120

Dùng Extended GCD:
gcd(17, 3120) = gcd(17, 3120 mod 17) = gcd(17, 6)
             = gcd(6, 17 mod 6) = gcd(6, 5)
             = gcd(5, 1) = 1

Backtracking:
1 = 6 - 1×5
  = 6 - 1×(17 - 2×6) = 3×6 - 17
  = 3×(3120 - 183×17) - 17 = 3×3120 - 549×17 - 17 = 3×3120 - 550×17

Vậy: -550×17 ≡ 1 (mod 3120)
     (-550 mod 3120) × 17 ≡ 1 (mod 3120)
     (3120 - 550) × 17 ≡ 1 (mod 3120)
     2570 × 17 ≡ 1 (mod 3120)
     
Hoặc: d = 2753 (thường được tính chính xác hơn)

Kiểm tra: 17 × 2753 = 46801 = 15 × 3120 + 1 ✓
```

#### **E. Kết Quả Sinh Khóa**

```
Public Key (để chia sẻ):
(e, n) = (17, 3233)

Private Key (giữ bí mật):
(d, n) = (2753, 3233)

Hoặc: (d, p, q) = (2753, 61, 53) - tối ưu hóa cho CRT
```

### 7.2 RSA Mã Hóa / Giải Mã

#### **A. Mã Hóa**

**Công Thức:**
```
Ciphertext C ≡ M^e (mod n)

Trong đó:
- M: Plaintext (0 < M < n)
- e: Public exponent
- n: Modulus
```

**Ví Dụ Chi Tiết:**
```
Plaintext:  M = 65
Public Key: (e=17, n=3233)

Tính C = 65^17 mod 3233:

Bằng Square-and-Multiply (nhanh):
65^17 = 65^16 × 65^1

65^1  = 65
65^2  = 4225 ≡ 1025 (mod 3233)
65^4  ≡ 1025^2 ≡ 1050625 ≡ 915 (mod 3233)
65^8  ≡ 915^2 ≡ 837225 ≡ 2045 (mod 3233)
65^16 ≡ 2045^2 ≡ 4182025 ≡ 841 (mod 3233)

65^17 = 65^16 × 65^1 ≡ 841 × 65 ≡ 54665 ≡ 2790 (mod 3233)

Ciphertext: C = 2790
```

#### **B. Giải Mã**

**Công Thức:**
```
Plaintext M ≡ C^d (mod n)

Trong đó:
- C: Ciphertext
- d: Private exponent
- n: Modulus
```

**Ví Dụ Chi Tiết:**
```
Ciphertext: C = 2790
Private Key: (d=2753, n=3233)

Tính M = 2790^2753 mod 3233:

Bằng Square-and-Multiply (bỏ qua chi tiết):
2790^2753 ≡ 65 (mod 3233)

Plaintext: M = 65 ✓
```

#### **C. Tại Sao Nó Hoạt Động?**

**Chứng Minh Toán Học:**
```
M ≡ C^d ≡ (M^e)^d ≡ M^(ed) (mod n)

Vì e × d ≡ 1 (mod φ(n)):
  e × d = 1 + k×φ(n) với k ≥ 1

Theo Định Lý Euler:
  Nếu gcd(M, n) = 1: M^φ(n) ≡ 1 (mod n)

Vậy:
  M^(ed) = M^(1 + k×φ(n)) = M × (M^φ(n))^k ≡ M × 1^k ≡ M (mod n)
  
→ Giải mã khôi phục plaintext gốc!
```

### 7.3 RSA Digital Signature

#### **A. Ký Số**

**Công Thức:**
```
Signature S ≡ H(M)^d (mod n)

Trong đó:
- M: Message cần ký
- H(M): Hash của message (SHA-256, v.v.)
- d: Private key exponent
- n: Modulus
```

**Ví Dụ:**
```
Message: "IMPORTANT MESSAGE"

Bước 1: Tính hash
  H = SHA-256(M) = 0x1A2B3C4D5E6F7A8B9CDEF0... (256 bits)
  (Dùng 256 bit đầu hoặc mod n)
  H ≈ 6827 (mod n=3233, giả định)

Bước 2: Ký
  S ≡ 6827^2753 (mod 3233)
  S ≡ 2598 (mod 3233)

Signature: S = 2598
```

#### **B. Xác Minh Chữ Ký**

**Công Thức:**
```
H' ≡ S^e (mod n)

Kiểm tra: H' = H(M)?
```

**Ví Dụ:**
```
Signature: S = 2598
Public Key: (e=17, n=3233)
Message: "IMPORTANT MESSAGE"

Bước 1: Xác minh chữ ký
  H' ≡ 2598^17 (mod 3233)
  H' ≡ 6827 (mod 3233)

Bước 2: Tính hash message
  H = SHA-256(M) ≈ 6827 (mod 3233)

Bước 3: So sánh
  H' (6827) = H (6827)? ✓ YES!
  
→ Chữ ký hợp lệ!
```

#### **C. Tại Sao Digital Signature Hoạt Động?**

```
S ≡ H^d (mod n)
S^e ≡ (H^d)^e ≡ H^(de) ≡ H (mod n)

Vì chỉ có holder của private key d mới có thể tính S
→ Chữ ký không thể giả mạo
→ Xác minh được tính toàn vẹn của message
```

### 7.4 Tấn Công RSA

####  **1. Brute Force (Vô Tích)**

**Không Khả Thi:**
```
RSA-2048: Thử tất cả 2^2048 khóa
→ 2^2048 phép tính ≈ 10^617 phép tính
→ Ngay cả quantum computer cũng không thể trong thời gian hợp lý

Thời gian: ∞ (trên thực tế)
```

####  **2. Factorization (Dựa Trên n)**

**Nguyên Lý:**
```
Nếu biết p và q:
- n = p × q → đã có n (công khai)
- φ(n) = (p-1)(q-1) → tính được
- d = e^(-1) mod φ(n) → crack!

→ Bộ khóa bị phá vỡ hoàn toàn
```

**Các Phương Pháp Factorization:**

```
1. Trial Division: O(√n)
   - Chia thử n cho các số nguyên tố
   - Không khả thi cho n lớn

2. Fermat's Method: O(√n), hiệu quả nếu (p-q) nhỏ
   - Tìm: n = a² - b² = (a+b)(a-b)
   - Nếu p, q gần nhau → a, b gần nhau → nhanh

3. Pollard's rho: O(n^(1/4))
   - Phương pháp xác suất
   - Hiệu quả hơn trial division

4. General Number Field Sieve (GNFS): 
   O(exp(1.9(log n)^(1/3)(log log n)^(2/3)))
   - Phương pháp nhanh nhất hiện biết
   - Nhưng vẫn rất chậm cho RSA-2048
```

**Tình Hình Thực Tế:**
```
RSA-200 (200 digits): 2005 - mất 18 tháng (grid computing 70 năm máy)
RSA-232 (232 digits): 2020 - mất 1000 CPU-years
RSA-768 (232 digits): 2009 - mất nhiều năm
RSA-2048 (617 digits): Chưa ai factorize công khai (2024)

Ước tính:
RSA-2048 với GNFS: ~10^22 năm CPU-time (không khả thi)
RSA-4096: ~10^51 năm CPU-time (vô cùng không khả thi)
```

####  **3. Small Public Exponent Attack (e=3)**

**Nguy Hiểm:**
```
Nếu e nhỏ (e=3), có thể recover M mà không cần d:

Nếu M < n^(1/3):
- C = M^3 không bị modulo (M^3 < n)
- C = M^3 → M = ∛C (tính căn bậc 3 bình thường)

Ví dụ:
n = 3233, e = 3
M = 10 < 3233^(1/3) ≈ 14.78? Không, 10 < 14
M^3 = 1000 < 3233? Yes!
C = 1000 → M = ∛1000 = 10 (không modulo!)
```

**Phòng Chống:**
```
1. Dùng e = 65537 (lớn hơn)
2. Thêm padding (OAEP) trước khi mã hóa
   - Làm cho M > n^(1/3)
   - Thêm tính ngẫu nhiên
```

####  **4. Small Private Exponent Attack (Wiener's Attack)**

**Nguy Hiểm:**
```
Nếu d < n^(1/4):
- Có thể recover d từ (e, n)
- Dựa trên continued fractions
- Mất ~log(n) phép tính

Ví dụ:
n = 3233 ≈ 4 (mod 10000)
n^(1/4) ≈ 7.57

Nếu d < 7, Wiener's attack hoạt động
```

**Phòng Chống:**
```
Dùng d đủ lớn:
- d > n^(1/4) (tối thiểu)
- Hoặc sử dụng CRT (Chinese Remainder Theorem) 
  để tối ưu hóa giải mã mà không giảm d
```

####  **5. Common Modulus Attack**

**Nguy Hiểm:**
```
Nếu 2 người dùng cùng n nhưng e₁ ≠ e₂:
- C₁ = M^e₁ mod n
- C₂ = M^e₂ mod n
- Có thể recover M từ C₁, C₂

Lý do:
- Nếu gcd(e₁, e₂) = 1, có a, b sao cho:
  a×e₁ + b×e₂ = 1
- C₁^a × C₂^b = M^(a×e₁ + b×e₂) = M^1 = M
```

**Phòng Chống:**
```
Mỗi người dùng có n, p, q riêng
Không chia sẻ modulus!
```

---

###  Kết Quả Kiểm Thử
**Kết quả thực nghiệm:**
![Kết quả 22](/home/lenovo/cryptography_project/results/test8-rsa1.png)
![Kết quả 23](/home/lenovo/cryptography_project/results/test8-rsa2.png)

### Kết Luận

**RSA:**
- ✓ Mã hóa bất đối xứng
- ✓ Ký số (authentication)
- ✓ Trao đổi khóa
- ✓ An toàn dựa trên factorization

**Khuyên dùng:**
- **Hiện nay:** RSA-2048 (đủ an toàn)
- **Dài hạn:** RSA-4096 (an toàn hơn)
- **Thay thế:** ECC (Elliptic Curve Cryptography) - nhanh hơn, nhỏ gọn hơn

**File code:** `Chuong7_MaRSA/RSA.py`

---
## CHƯƠNG 8: HÀM BĂM (CRYPTOGRAPHIC HASH FUNCTIONS)

### Giới Thiệu

Hàm băm mật mã là hàm một chiều chuyên dụng cho:
- **Xác minh toàn vẹn:** Phát hiện nếu dữ liệu bị thay đổi
- **Chữ ký số:** Hash message trước khi ký
- **Mật khẩu:** Lưu hash password thay vì plaintext
- **Proof-of-Work:** Bitcoin, blockchain


### 8.1 Định Nghĩa Hàm Băm Mật Mã
 **Hàm Băm h: {0,1}* → {0,1}^n**

**Ba Tính Chất Cần Thiết:**

####  **1. Preimage Resistance (One-way)**

**Định Nghĩa:**
```
Cho y = h(x), khó tìm x sao cho h(x) = y

Độ khó: O(2^n)
```

**Ví Dụ:**
```
SHA-256: n = 256 bits
Độ khó: 2^256 ≈ 1.16 × 10^77 phép tính

Thực tế:
- Siêu máy tính: 10^18 phép/giây
- Cần: 10^77 / 10^18 = 10^59 giây ≈ 10^51 năm!
- Năng lượng cần: Vô cùng lớn
```

**Ứng Dụng:**
```
Lưu trữ mật khẩu:
- Database lưu h(password) thay vì plaintext
- Ngay cả nếu DB bị leak, attacker không thể reverse
```

####  **2. Second Preimage Resistance**

**Định Nghĩa:**
```
Cho x, khó tìm x' ≠ x sao cho h(x) = h(x')

Độ khó: O(2^n) - tương tự Preimage Resistance
```

**Ứng Dụng:**
```
Chữ ký số:
- Để giả mạo chữ ký, attacker cần tìm x' có hash = h(x)
- Với Preimage Resistance, điều này không khả thi
```

####  **3. Collision Resistance**

**Định Nghĩa:**
```
Khó tìm x ≠ y sao cho h(x) = h(y)

Độ khó: O(2^(n/2)) - Birthday attack!
```

**Tại Sao Birthday Paradox?**
```
Tập hợp n-bit có 2^n giá trị
Sau √(2^n) = 2^(n/2) mẫu, xác suất collision > 50%

Ví dụ: SHA-256
- 2^256 giá trị có thể
- Sau 2^128 ≈ 3.4 × 10^38 mẫu, xác suất collision > 50%

Thực tế:
- Siêu máy tính: 10^18 phép/giây
- Cần: 3.4 × 10^38 / 10^18 ≈ 3.4 × 10^20 giây ≈ 10^12 năm
- Vẫn rất không khả thi!

So sánh:
- MD5 (128-bit): Collision trong vài giây (lỗi thời!)
- SHA-1 (160-bit): Collision trong 2^61 (kinh tế hơn)
- SHA-256 (256-bit): Collision trong 2^128 (vô cùng an toàn)
```

### 8.2 Merkle-Damgård Construction

####  **A. Cấu Trúc Chuẩn**

```
Message M
    ↓
[Padding]
    ↓
[Split thành khối k bytes]
    ↓
[IV - Initialization Vector]
    ↓
[For each block Bᵢ]:
  H ← f(H, Bᵢ)  [Compression function]
    ↓
[Output: H]
```

####  **B. Padding Chi Tiết**

**Ví Dụ: M = "ABC" (3 bytes)**

```
Bước 1: Thêm bit '1'
  M = "ABC" = 0x414243
  M || 1 = 0x41424380 (thêm byte 10000000)

Bước 2: Thêm bits '0' để đạt length ≡ -64 (mod 512)
  Hiện tại: 4 bytes = 32 bits
  Cần: 448 bits (mod 512) = (448 - 32) / 8 = 52 bytes
  Thêm 52 bytes của 0x00

Bước 3: Thêm độ dài (64-bit big-endian)
  Độ dài M ban đầu: 3 bytes = 24 bits = 0x0000000000000018
  
Result: 64 bytes = 512 bits tổng cộng
```

####  **C. Compression Function f(H, B)**

**Đầu vào:**
- H: Hash hiện tại (từ vòng trước)
- B: Khối tin nhắn (512 bits)

**Đầu ra:**
- H': Hash cập nhật (để dùng vòng sau)

**Tính chất:**
```
Nếu f là collision-resistant
→ Toàn bộ Merkle-Damgård construction cũng collision-resistant

Định lý Merkle: "Merkle Construct Theorem"
```

---

### 8.3 SHA-1 vs SHA-256 vs SHA-512

####  **A. So Sánh**

| Tiêu chí | SHA-1 | SHA-256 | SHA-512 |
|----------|-------|---------|---------|
| **Output** | 160-bit | 256-bit | 512-bit |
| **Block** | 512-bit | 512-bit | 1024-bit |
| **Word** | 32-bit | 32-bit | 64-bit |
| **Vòng** | 80 | 64 | 80 |
| **Status** | ✗ Lỗi thời | ✓ Safe | ✓✓ Very Safe |

####  **B. SHA-1 (Lỗi Thời)**

**Collision Found (2017):**
```
Google SHAttered attack - tìm 2 PDF khác nhau có SHA-1 = nhau

Effort: 2^63 (thay vì 2^80 kỳ vọng) - 9 tỷ tỷ hash

Timeline:
- 2005: Lý thuyết collision O(2^52)
- 2017: SHAttered attack thực tế
- 2024: Không nên dùng SHA-1
```

####  **C. SHA-256 (Hiện Nay)**

**Công Thức:**
```
1. Padding: Message || 1 || 0...0 || length
   (length là 64-bit big-endian)

2. Parse thành 512-bit blocks

3. 8 working variables (a-h): mỗi 32-bit
   IV (Initialization Vector): 8 giá trị 32-bit chuẩn
   
4. For each 512-bit block:
   - Expand thành 64 từ 32-bit (message schedule)
   - For round t = 0 to 63:
     T1 = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t]
     T2 = Σ₀(a) + Maj(a,b,c)
     h = g; g = f; f = e; e = d + T1
     d = c; c = b; b = a; a = T1 + T2
   - Update working variables

5. Kết hợp với IV ban đầu

Output: 256 bits (32 bytes)
```

**Hàm Cơ Bản:**
```
Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)  [Conditional]
Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)  [Majority]
Σ₀(x) = ror(x, 2) ⊕ ror(x, 13) ⊕ ror(x, 22)
Σ₁(x) = ror(x, 6) ⊕ ror(x, 11) ⊕ ror(x, 25)
σ₀(x) = ror(x, 7) ⊕ ror(x, 18) ⊕ shr(x, 3)
σ₁(x) = ror(x, 17) ⊕ ror(x, 19) ⊕ shr(x, 10)
```

####  **D. SHA-512 (An Toàn Cao)**

**Khác SHA-256:**
```
- Word: 64-bit (thay vì 32-bit)
- Block: 1024-bit (thay vì 512-bit)
- Vòng: 80 (thay vì 64)
- Output: 512-bit (thay vì 256-bit)
- Constants K[t]: 80 giá trị 64-bit
```

**Ưu Điểm:**
```
- Output lớn (512-bit) → Birthday attack cost 2^256
- Từ 64-bit → Tính toán lạ trên 64-bit CPU
- Mạnh hơn SHA-256 để chống future attacks
```

### 8.4 Ứng Dụng Hàm Băm

####  **A. Xác Minh Toàn Vẹn**

```
Gửi file + hash:
1. Tạo: h = SHA-256(file)
2. Gửi: file + h

Nhận:
1. Tính: h' = SHA-256(file nhận)
2. Kiểm: h' = h?
   - Nếu có: file nguyên vẹn ✓
   - Nếu không: file bị thay đổi ✗
```

####  **B. Chữ Ký Số**

```
Ký:
1. h = SHA-256(message)
2. signature = RSA_sign(h, private_key)

Xác minh:
1. h' = SHA-256(message)
2. Kiểm: RSA_verify(signature, h', public_key)?
   - RSA sẽ tính h'' = RSA_decrypt(signature)
   - So sánh: h' = h''?
```

####  **C. Lưu Trữ Mật Khẩu**

```
Đăng ký:
1. Người dùng nhập: password
2. Lưu: h = SHA-256(password + salt)  (với salt ngẫu nhiên)

Đăng nhập:
1. Người dùng nhập: password_input
2. Tính: h' = SHA-256(password_input + salt)
3. Kiểm: h' = h (từ database)?
   - Nếu có: Đăng nhập thành công ✓
   - Nếu không: Sai mật khẩu ✗

Lợi ích:
- Server không lưu plaintext password
- Nếu DB leak: attacker không thể reverse SHA-256
- Salt ngẫu nhiên chống rainbow table attack
```

####  **D. Blockchain / Bitcoin**

```
Proof-of-Work:
1. Block = [data, nonce, prev_hash]
2. Tìm nonce sao cho: SHA-256(Block) < target
   - Phải try nhiều nonce
   - Miner nào tìm được trước → nhận reward

Hash chain:
1. Block 1: hash₁ = SHA-256(Block1)
2. Block 2: hash₂ = SHA-256(Block2 || hash₁)
3. Block 3: hash₃ = SHA-256(Block3 || hash₂)
4. ...

Tính chất:
- Nếu thay đổi Block cũ → hash cũ thay đổi → hash tiếp theo thay đổi → chuỗi phá vỡ
- Để giả mạo, phải tính lại tất cả block sau → rất mắc chi phí
```

### 8.5 Tấn Công Hàm Băm

####  **1. Brute Force Preimage**

```
Cho y = h(x), tìm x:
- Thử tất cả 2^n giá trị có thể
- SHA-256: 2^256 ≈ vô cùng không khả thi
```

####  **2. Birthday Attack (Collision)**

```
Nguyên lý:
- Tạo 2^(n/2) random input
- Tính hash của từng cái
- Tìm 2 cái có hash giống nhau

Effort: 2^(n/2)

SHA-256:
- 2^128 ≈ 3.4 × 10^38 phép tính
- Vẫn không khả thi

MD5 (lỗi thời):
- 2^64 ≈ vài tỷ phép tính
- Tìm collision trong vài giây!
```

####  **3. Length Extension Attack**

```
Nếu hàm dùng Merkle-Damgård và ta biết h(M):
- Có thể tính h(M || M') mà không biết M!
- Bằng cách mở rộng padding

Ví dụ:
- h(password || user_data) được sử dụng
- Attacker tính h(password || user_data || malicious)
- Giống hệt như nếu server hash(password || user_data || malicious)

Phòng chống:
- HMAC (Hash-based Message Authentication Code)
- h(password || message) → không an toàn
- HMAC(password, message) → an toàn!
```

####  **4. Rainbow Table & Dictionary Attack**

```
Rainbow Table:
- Tạo bảng: [plaintext → hash] cho tất cả password phổ biến
- Lookup: Nếu h(x) nằm trong bảng → tìm được x

Phòng Chống:
- Thêm salt: h(password + salt)
- Salt ngẫu nhiên cho mỗi user
- Với salt, attacker phải tính bảng riêng cho mỗi salt!
```

### Kết Quả Kiểm Thử
**Kết quả thực nghiệm:**
![Kết quả 22](/home/lenovo/cryptography_project/results/test8-1.png)

### 8.6 Thống Kê Hash Security

| Hash | Output | Birthday | Status | Năm |
|------|--------|----------|--------|-----|
| MD5 | 128-bit | 2^64 | ✗ Broken | 1992 |
| SHA-1 | 160-bit | 2^80 | ✗ Lỗi thời | 1995 |
| SHA-256 | 256-bit | 2^128 | ✓ Safe | 2001 |
| SHA-512 | 512-bit | 2^256 | ✓✓ Very Safe | 2001 |
| BLAKE2 | 256-512 | 2^128-256 | ✓ Fast & Safe | 2012 |

### Kết Luận

**Hàm Băm Mật Mã:**
- ✓ Một chiều (không thể reverse)
- ✓ Xác định (input giống → output giống)
- ✓ Tốc độ (tính nhanh)
- ✓ Xác minh toàn vẹn (detect thay đổi)
- ✓ Ứng dụng rộng (chữ ký, mật khẩu, blockchain)

**Khuyên dùng:**
- **Hiện nay:** SHA-256, SHA-512 (chuẩn NIST)
- **Thay thế:** BLAKE2 (nhanh hơn, hiện đại hơn)
- **Tránh:** MD5, SHA-1 (lỗi thời, đã bị crack)

**File code:** `Chuong8_HamBam/hash_signature_keymanagement.py`
---

## BẢNG SO SÁNH TOÀN DIỆN CÁC HỆ MẬT

| Hệ Thống | Năm | Khóa | Khối | Vòng | Bảo Mật (2024) | Ghi chú |
|----------|-----|------|------|------|----------------|---------|
| Caesar | ~0 BC | 26 | N/A | 1 | ✗ Trivial | Brute force dễ |
| Vigenère | 1553 | variable | N/A | variable | ✗ Weak | Frequency analysis |
| DES | 1977 | 56 | 64 | 16 | ✗ Broken | 2^56 khóa |
| 3DES | 1998 | 168 | 64 | 48 | ⚠ Legacy | 2^112 nhưng chậm |
| AES-128 | 2001 | 128 | 128 | 10 | ✓ Strong | Standard hiện tại |
| AES-256 | 2001 | 256 | 128 | 14 | ✓✓ Very Strong | Dài hạn |
| RSA-2048 | 1977 | 2048 | variable | 1 | ✓ Safe | Phụ thuộc factorization |
| ECC-256 | 2000 | 256 | variable | 1 | ✓ Strong | Nhanh hơn RSA |
| SHA-256 | 2001 | N/A | 512 | 64 | ✓ Safe | Standard |
| SHA-512 | 2001 | N/A | 1024 | 80 | ✓✓ Safe | Mạnh hơn SHA-256 |
| Knapsack | 1978 | variable | variable | 1 | ✗ BROKEN | Shamir 1984 |

---

## TỔNG KẾT BẢO MẬT

### Tấn Công Phổ Biến

| Tấn Công | Mục Tiêu | Độ Phức Tạp | Phòng Chống |
|----------|----------|------------|-----------|
| Brute Force | Khóa | 2^k | Khóa dài |
| Frequency Analysis | Substitution | O(n) | Vigenère+ |
| Meet-in-the-Middle | 2DES | 2^57 | 3DES |
| Differential Cryptanalysis | DES/AES | Lý thuyết | Thiết kế cẩn thận |
| Linear Cryptanalysis | DES | 2^43 dữ liệu | Thiết kế cẩn thận |
| Factorization | RSA | O(exp(...)) | p, q lớn |
| Birthday Attack | Hash | 2^(n/2) | Hash dài |
| Side-Channel | Any | Thực tế | Constant-time code |

---

### Độ Phức Tạp Tính Toán

| Thuật Toán | Độ Phức Tạp | Thời Gian (Ví Dụ) |
|-----------|-----------|------------------|
| GCD (Euclidean) | O(log n) | ~1 microsecond |
| Prime Check (Trial Division) | O(√n) | ~1 millisecond (n = 10^9) |
| Factorization (Trial Division) | O(√n) | ~1 second (n = 10^12) |
| Factorization (GNFS) | O(exp(1.9(log n)^(1/3))) | ~centuries (RSA-2048) |
| DES Encryption | O(1) [fixed rounds] | ~10 microseconds |
| AES Encryption | O(1) [fixed rounds] | ~20 microseconds |
| RSA Encryption (2048-bit) | O(log e) [fast exp] | ~100 microseconds |
| SHA-256 Hashing | O(n) [linear] | ~10 microseconds (512 bytes) |

---

## KẾT LUẬN BÁO CÁO

Dự án này cung cấp:
✅ **Kiến thức lý thuyết toàn diện** từ cơ bản đến nâng cao  
✅ **Code triển khai từng thuật toán** (không dùng thư viện)  
✅ **Ứng dụng thực tế** (mã hóa, ký, băm, quản lý khóa)  
✅ **Tham chiếu chi tiết** đến tài liệu gốc  
✅ **Output kiểm chứng** cho mỗi thuật toán  

---