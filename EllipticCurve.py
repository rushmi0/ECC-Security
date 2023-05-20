from random import getrandbits

class EllipticCurve:

    # Secp256k1
    def __init__(self):
        self.A = 0
        self.B = 7
        # 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
        self.P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
        self.N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        self.G = {"x": 55066263022277343669578718895168534326250603453777594175500187360389116729240,
                  "y": 32670510020758816978083085130507043184471273380659243275938904335757337482424}

    # การคำนวณหลัก: Elliptic Curve cryptography
    def modinv(self, A: int, N=None) -> int:
        if N is None:
            N = self.P
            
        def extended_gcd(a, b):
            if b == 0:
                return a, 1, 0
            gcd, x, y = extended_gcd(b, a % b)
            return gcd, y, x - (a // b) * y

        gcd, x, _ = extended_gcd(A, N)
        result = x % N
        return result if result >= 0 else result + N

    def double(self, point: int) -> dict:
        lam_numer = (3 * point["x"] ** 2 + self.A) % self.P
        lam_denom = (2 * point["y"]) % self.P
        lam = (lam_numer * self.modinv(lam_denom)) % self.P

        xR = (lam ** 2 - 2 * point["x"]) % self.P
        yR = (lam * (point["x"] - xR) - point["y"]) % self.P
        return {"x": xR, "y": yR}

    def add(self, point1: int, point2: int) -> dict:
        if point1 == point2:
            return self.double(point1)
        m = ((point2["y"] - point1["y"]) * self.modinv(point2["x"] - point1["x"])) % self.P
        xR = (m ** 2 - point1["x"] - point2["x"]) % self.P
        yR = (m * (point1["x"] - xR) - point1["y"]) % self.P
        return {"x": xR, "y": yR}

    def multiply(self, k: int, point=None) -> dict:
        if not point:
            point = self.G
        binary = bin(k)[2:]
        current = point
        for bit in binary[1:]:
            current = self.double(current)
            if bit == "1":
                current = self.add(current, point)
        return current

    def publickey(self, k: int) -> str:
        point = self.multiply(k)
        return f"04{hex(point['x'])[2:]}{hex(point['y'])[2:]}"

    def compress_point(self, public_key: str) -> str:
        if public_key[0:2] != '04':
            raise ValueError('Invalid Public Key')
        x = int(public_key[2:66], 16)
        y = int(public_key[66:], 16)

        if (y % 2) == 0:
            public_key = '02' + format(x, '064x')
        else:
            public_key = '03' + format(x, '064x')
        return public_key

    # การคำนวณหลัก: ECDSA
    def signature(self, private_key: int, message: int) -> dict:
        z = message
        k = 47015016470583645446654890691026687320549785451357444754315920288772675949303
        #k = getrandbits(256)
        r, s = 0, 0
        while r == 0 or s == 0:
            point = self.multiply(k)
            k_inv = self.modinv(k, self.N)
            r = point['x'] % self.N
            s = ((z + r * private_key) * k_inv) % self.N
        return {'r': r, 's': s}

    def to_der_format(self, signature: dict) -> str:
        r = signature['r']
        s = signature['s']

        rb = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big', signed=False)
        sb = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big', signed=False)

        der_r = b'\x02' + len(rb).to_bytes(1, byteorder='big', signed=False) + rb
        der_s = b'\x02' + len(sb).to_bytes(1, byteorder='big', signed=False) + sb
        der_sig = b'\x30' + (len(der_r) + len(der_s)).to_bytes(1, byteorder='big', signed=False) + der_r + der_s
        return der_sig.hex()

    def verify(self, publickey: dict, message: int, signature: dict) -> bool:
        m = message
        r = signature['r']
        s = signature['s']

        w = self.modinv(s, self.N)
        u1 = (m * w) % self.N
        u2 = (r * w) % self.N

        point1 = self.multiply(u1)
        point2 = self.multiply(u2, publickey)

        point = self.add(point1, point2)
        x = point['x'] % self.N
        return x == r


curve = EllipticCurve()
# private_key = getrandbits(256)

private_key = 111798668807017442629247557499629816624858299873427551140682199544191852692645
# print(hex(private_key)[2:])
print("Private key:", private_key)
message = 67190017246757783140308448604179518505030850719375738244213419124624541387587

# สร้าง Public key
P = curve.multiply(private_key)
print("Key Point", P)

public_key = curve.publickey(private_key)
print("[U] Public Key:", public_key)

compress = curve.compress_point(public_key)
print("[C] Public Key:", compress)

sign = curve.signature(private_key, message)
der = curve.to_der_format(sign)
print("Der format:", der)

isValid = curve.verify(P, message, sign)
print("Signature is:", isValid)
