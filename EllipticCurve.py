from random import getrandbits

class EllipticCurve:

    # Constructor: Secp256k1
    def __init__(self):
        self.A = 0
        self.B = 7
        self.P = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
        self.N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        self.G = {"x": int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
                  "y": int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)}

    # การคำนวณหลัก: Elliptic Curve cryptography
    def modinv(self, A: int, N=None) -> int:
        if N is None: N = self.P
        lm, hm = 1, 0; low, high = A % N, N
        while low > 1:
            ratio = high // low
            nm, new = hm - lm * ratio, high - low * ratio; lm, low, hm, high = nm, new, lm, low
        return lm % N

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
        # สร้าง Public key
        point = self.multiply(k)
        return "04" + hex(point['x'])[2:] + hex(point['y'])[2:]

    # การคำนวณหลัก: ECDSA
    def signature(self, private_key: int, message: int) -> dict:
        z = message
        # k = int("3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044",16)
        k = getrandbits(256); r = 0; s = 0
        while r == 0 or s == 0:
            point = self.multiply(k)
            k_inv = self.modinv(k, self.N)
            r = point['x'] % self.N
            s = ((z + r * private_key) * k_inv) % self.N; #k += 1
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

def main():
    curve = EllipticCurve()
    private_key = getrandbits(256)
    #private_key = 111798668807017442629247557499629816624858299873427551140682199544191852692645
    print("Private key:", private_key)
    message = 67190017246757783140308448604179518505030850719375738244213419124624541387587

    # สร้าง Public key
    P = curve.multiply(private_key)
    print("Public Key Point", P)

    public_key = curve.publickey(private_key)
    print("Public Key:", public_key)

    # สร้างลายเซ็น ECDSA
    sig = curve.signature(private_key, message)
    print("ECDSA signature", sig)

    # ตรวจสอบเซ็น ECDSA
    ver = curve.verify(P, message, sig)
    print(f'signature is {ver}')

    # พร้อมใช้
    sig_der = curve.to_der_format(sig)
    print(f'signature Der format: {sig_der}')


if __name__ == "__main__":
    main()
