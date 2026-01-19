"""
CHƯƠNG 2: CƠ SỞ TOÁN HỌC
Các nội dung cơ bản về toán học trong mật mã
"""

# ========== 2.1: SỐ HỌC CÁC SỐ NGUYÊN ==========

class MathematicsBasics:
    """Lớp chứa các hàm toán học cơ bản cho mật mã"""
    
    # 2.1.1 - Một số khái niệm cơ bản về chia hết
    @staticmethod
    def is_divisible(a, b):
        """
        Kiểm tra a có chia hết cho b hay không
        Công thức: a ≡ 0 (mod b) hay a = b*k (k là số nguyên)
        """
        return a % b == 0
    
    @staticmethod
    def get_divisors(n):
        """
        Tìm tất cả các ước số của n
        Ví dụ: n = 12 → ước số: 1, 2, 3, 4, 6, 12
        """
        divisors = []
        for i in range(1, n + 1):
            if n % i == 0:
                divisors.append(i)
        return divisors
    
    # 2.1.2 - Ước số chung lớn nhất (GCD - Greatest Common Divisor)
    @staticmethod
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
    
    @staticmethod
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
    
    # 2.1.3 - Số nguyên tố (Prime Numbers)
    @staticmethod
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
    
    @staticmethod
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
    
    @staticmethod
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
    
    # ========== 2.2: SỐ HỌC MODUL (MODULAR ARITHMETIC) ==========
    
    @staticmethod
    def modular_addition(a, b, m):
        """
        Phép cộng mô đun: (a + b) mod m
        Tính chất: (a mod m + b mod m) mod m = (a + b) mod m
        """
        return (a + b) % m
    
    @staticmethod
    def modular_subtraction(a, b, m):
        """
        Phép trừ mô đun: (a - b) mod m
        Chú ý: Kết quả luôn không âm
        """
        return (a - b) % m
    
    @staticmethod
    def modular_multiplication(a, b, m):
        """
        Phép nhân mô đun: (a * b) mod m
        Tính chất: (a mod m) * (b mod m) mod m = (a * b) mod m
        """
        return (a * b) % m
    
    @staticmethod
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
    
    @staticmethod
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
    
    # ========== 2.3: ĐỒNG DƯ TUYẾN TÍNH (LINEAR CONGRUENCE) ==========
    
    @staticmethod
    def solve_linear_congruence(a, b, m):
        """
        Giải phương trình đồng dư tuyến tính: a*x ≡ b (mod m)
        
        Trường hợp 1: gcd(a, m) = 1
            → Có duy nhất 1 nghiệm: x ≡ b * a^(-1) (mod m)
        
        Trường hợp 2: gcd(a, m) = d > 1
            - Nếu d không chia hết b → Vô nghiệm
            - Nếu d chia hết b → Có d nghiệm
        
        Ví dụ: 3x ≡ 9 (mod 6)
        gcd(3, 6) = 3, 3|9 → có 3 nghiệm
        """
        gcd, x, _ = MathematicsBasics.gcd_extended(a, m)
        
        if b % gcd != 0:
            return None  # Vô nghiệm
        
        # Chia tất cả cho gcd
        a //= gcd
        b //= gcd
        m //= gcd
        
        # Tìm nghịch đảo của a mod m (mới)
        inv_a = MathematicsBasics.modular_inverse(a, m)
        
        if inv_a is None:
            return None
        
        # Nghiệm: x = b * inv_a mod m
        solutions = []
        base_solution = (b * inv_a) % m
        
        # Nếu có nhiều nghiệm, liệt kê chúng
        for i in range(gcd):
            solutions.append((base_solution + i * m) % (m * gcd))
        
        return solutions
    
    # ========== 2.4: MA TRẬN (MATRICES) ==========
    
    @staticmethod
    def matrix_multiply(A, B, mod=None):
        """
        Nhân hai ma trận: C = A × B
        
        Điều kiện: Số cột của A = số hàng của B
        Độ phức tạp: O(n³) cho ma trận n×n
        
        Công thức: C[i][j] = Σ A[i][k] * B[k][j]
        
        Nếu mod != None: kết quả sẽ được mod mod
        """
        rows_A = len(A)
        cols_A = len(A[0])
        rows_B = len(B)
        cols_B = len(B[0])
        
        if cols_A != rows_B:
            raise ValueError("Không thể nhân: số cột A ≠ số hàng B")
        
        # Tạo ma trận kết quả với giá trị 0
        C = [[0 for _ in range(cols_B)] for _ in range(rows_A)]
        
        for i in range(rows_A):
            for j in range(cols_B):
                for k in range(cols_A):
                    C[i][j] += A[i][k] * B[k][j]
                
                # Áp dụng modulo nếu cần
                if mod:
                    C[i][j] %= mod
        
        return C
    
    @staticmethod
    def matrix_determinant_2x2(matrix):
        """
        Tính định thức của ma trận 2×2
        
        |a b|
        |c d| = ad - bc
        """
        if len(matrix) != 2 or len(matrix[0]) != 2:
            raise ValueError("Ma trận phải là 2×2")
        
        a, b = matrix[0]
        c, d = matrix[1]
        
        return a * d - b * c
    
    @staticmethod
    def matrix_inverse_2x2(matrix, mod):
        """
        Tính ma trận nghịch đảo 2×2 trong số học mô đun
        
        Cho ma trận A:
        |a b|
        |c d|
        
        A^(-1) = 1/det(A) * |d  -b|
                              |-c  a|
        
        Trong mô đun m:
        A^(-1) = det(A)^(-1) mod m * |d  -b| mod m
                                       |-c  a|
        """
        det = MathematicsBasics.matrix_determinant_2x2(matrix)
        det_mod = det % mod
        
        # Tìm nghịch đảo của det mod m
        det_inv = MathematicsBasics.modular_inverse(det_mod, mod)
        
        if det_inv is None:
            return None  # Ma trận không có nghịch đảo
        
        a, b = matrix[0]
        c, d = matrix[1]
        
        # Tính ma trận nghịch đảo
        inv_matrix = [
            [(det_inv * d) % mod, (-det_inv * b) % mod],
            [(-det_inv * c) % mod, (det_inv * a) % mod]
        ]
        
        # Đảm bảo tất cả giá trị dương
        for i in range(2):
            for j in range(2):
                inv_matrix[i][j] = (inv_matrix[i][j] % mod + mod) % mod
        
        return inv_matrix


# ========== BÀI TẬP VÀ KIỂM THỬ ==========

def test_mathematics_basics():
    """Test các hàm toán học cơ bản"""
    
    print("="*70)
    print("KIỂM TẬP: CƠ SỞ TOÁN HỌC TRONG MẬT MÃ")
    print("="*70)
    
    mb = MathematicsBasics()
    
    # Test 1: Ước số chung lớn nhất
    print("\n[TEST 1] Ước Số Chung Lớn Nhất (GCD)")
    print("-" * 70)
    test_pairs = [(48, 18), (100, 75), (1071, 462)]
    for a, b in test_pairs:
        gcd = mb.gcd_euclidean(a, b)
        gcd_ext, x, y = mb.gcd_extended(a, b)
        print(f"gcd({a}, {b}) = {gcd}")
        print(f"Extended GCD: {a}*({x}) + {b}*({y}) = {gcd_ext}")
        print(f"Kiểm chứng: {a*x + b*y} = {gcd_ext} ✓")
    
    # Test 2: Kiểm tra số nguyên tố
    print("\n[TEST 2] Kiểm Tra Số Nguyên Tố")
    print("-" * 70)
    test_numbers = [2, 17, 25, 97, 100, 101]
    for n in test_numbers:
        is_prime = mb.is_prime_simple(n)
        print(f"{n} là số nguyên tố: {is_prime}")
    
    # Test 3: Phân tích thừa số nguyên tố
    print("\n[TEST 3] Phân Tích Thừa Số Nguyên Tố")
    print("-" * 70)
    numbers_to_factor = [60, 100, 97]
    for n in numbers_to_factor:
        factors = mb.prime_factors(n)
        print(f"{n} = {' × '.join(map(str, factors))}")
    
    # Test 4: Số học mô đun
    print("\n[TEST 4] Số Học Mô Đun")
    print("-" * 70)
    print(f"(17 + 25) mod 7 = {mb.modular_addition(17, 25, 7)}")
    print(f"(25 - 17) mod 7 = {mb.modular_subtraction(25, 17, 7)}")
    print(f"(12 × 18) mod 23 = {mb.modular_multiplication(12, 18, 23)}")
    print(f"2^100 mod 1000 = {mb.modular_exponentiation(2, 100, 1000)}")
    
    # Test 5: Nghịch đảo mô đun
    print("\n[TEST 5] Nghịch Đảo Mô Đun")
    print("-" * 70)
    a, m = 7, 26
    inv = mb.modular_inverse(a, m)
    print(f"Tìm x sao cho: {a} * x ≡ 1 (mod {m})")
    print(f"x = {inv}")
    print(f"Kiểm chứng: ({a} × {inv}) mod {m} = {(a * inv) % m} ✓")
    
    # Test 6: Giải phương trình đồng dư tuyến tính
    print("\n[TEST 6] Giải Phương Trình Đồng Dư Tuyến Tính")
    print("-" * 70)
    a, b, m = 3, 9, 6
    solutions = mb.solve_linear_congruence(a, b, m)
    print(f"Giải: {a}x ≡ {b} (mod {m})")
    if solutions:
        print(f"Nghiệm: x ≡ {solutions} (mod {m//mb.gcd_euclidean(a, m)})")
    else:
        print("Phương trình vô nghiệm")
    
    # Test 7: Nhân ma trận
    print("\n[TEST 7] Nhân Ma Trận")
    print("-" * 70)
    A = [[1, 2], [3, 4]]
    B = [[5, 6], [7, 8]]
    C = mb.matrix_multiply(A, B)
    print(f"A = {A}")
    print(f"B = {B}")
    print(f"A × B = {C}")
    
    # Test 8: Ma trận nghịch đảo
    print("\n[TEST 8] Ma Trận Nghịch Đảo (Mô Đun)")
    print("-" * 70)
    matrix = [[5, 8], [3, 5]]
    mod = 26
    inv_matrix = mb.matrix_inverse_2x2(matrix, mod)
    print(f"Ma trận: {matrix}")
    print(f"Mod: {mod}")
    if inv_matrix:
        print(f"Ma trận nghịch đảo: {inv_matrix}")
        # Kiểm chứng
        product = mb.matrix_multiply(matrix, inv_matrix, mod)
        print(f"Kiểm chứng (A × A^(-1) mod {mod}): {product}")
    else:
        print("Ma trận không có nghịch đảo")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    test_mathematics_basics()