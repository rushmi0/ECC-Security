class Secp521r1:
    
    def __init__(self):
        self.A = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
        self.B = 659873501825845607906911397389668342420684974786564569494856176035728606701266678260266724488125155903932043814080613
        self.P = 2**521 - 1
        self.N = 2**519 - 337554763258501705789107630418782636071904961214051226618635150085779108655765
        self.G = {"x": 337554763258501705789107630418782636071904961214051226618635150085779108655765,
                  "y": 1195318747956072426051636402832100617917103246846524752233511391513351302131269}

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


""" ตัวอย่างการใช้งาน """"
curve = Secp521r1()
private_key = "e38b1a0e3169055bbec35266002ee43519a545dd30c6315942ce82da60b5853d"
k = int(private_key, 16)
public_key = curve.multiply(k)

x = hex(public_key["x"])[2:]
y = hex(public_key["y"])[2:]

print(f"X coordinate: {x}")
print(f"Y coordinate: {y}")
