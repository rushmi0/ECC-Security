class Secp256k1:
    def __init__(self):
        self.A = 0
        self.B = 7
        self.P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
        self.N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        self.G = {"x": 55066263022277343669578718895168534326250603453777594175500187360389116729240,
                  "y": 32670510020758816978083085130507043184471273380659243275938904335757337482424}

    def modinv(self, a):
        a = a % self.P if a < 0 else a
        prevy, y = 0, 1
        m = self.P
        while a > 1:
            q = m // a; y, prevy = prevy - q * y, y; a, m = m % a, a
        return y

    def double(self, point):
        slope = ((3 * point["x"] ** 2) * self.modinv((2 * point["y"]))) % self.P
        x = (slope ** 2 - (2 * point["x"])) % self.P
        y = (slope * (point["x"] - x) - point["y"]) % self.P
        return {"x": x, "y": y}

    def add(self, point1, point2):
        if point1 == point2:
            return self.double(point1)
        slope = ((point1["y"] - point2["y"]) * self.modinv(point1["x"] - point2["x"])) % self.P
        x = (slope ** 2 - point1["x"] - point2["x"]) % self.P
        y = ((slope * (point1["x"] - x)) - point1["y"]) % self.P
        return {"x": x, "y": y}

    def multiply(self, k, point=None):
        if not point:
            point = self.G
        current = point
        binary = bin(k)[2:]
        for bin_prv in binary[1:]:
            current = self.double(current)
            if bin_prv == "1":
                current = self.add(current, point)
        return current

curve = Secp256k1()
private_key = "e38b1a0e3169055bbec35266002ee43519a545dd30c6315942ce82da60b5853d"
k = int(private_key, 16)
public_key = curve.multiply(k)

x = hex(public_key["x"])[2:]
y = hex(public_key["y"])[2:]

print(f"X coordinate: {x}")
print(f"Y coordinate: {y}")
