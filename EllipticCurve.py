from random import getrandbits

class ECSecp256k1:
    def __init__(self):
        self.A = 0
        self.B = 7
        self.P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
        self.N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        self.G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
                  32670510020758816978083085130507043184471273380659243275938904335757337482424)


    """ ------------------- การคำนวณหลัก Elliptic Curve cryptography ------------------- """
    
    def modinv(self, A, N=None):
        if N is None:
            N = self.P
        return pow(A, -1, N)

    def double(self, point):
        x, y = point
        lam_numer = (3 * x * x + self.A) % self.P
        lam_denom = (2 * y) % self.P
        lam = (lam_numer * self.modinv(lam_denom)) % self.P

        xR = (lam * lam - 2 * x) % self.P
        yR = (lam * (x - xR) - y) % self.P
        return (xR, yR)

    def add(self, point1, point2):
        if point1 == point2:
            return self.double(point1)
        x1, y1 = point1
        x2, y2 = point2

        m = ((y2 - y1) * self.modinv(x2 - x1)) % self.P
        xR = (m * m - x1 - x2) % self.P
        yR = (m * (x1 - xR) - y1) % self.P
        return (xR, yR)

    def multiply(self, k, point=None):
        if point is None:
            point = self.G
        binary = bin(k)[2:]
        current = point
        for bit in binary[1:]:
            current = self.double(current)
            if bit == "1":
                current = self.add(current, point)
        return current

    
    """ ------------------- ส่วนขยาย ------------------- """
    
    def publickey(self, k: int) -> str:
        point = self.multiply(k)
        publickey_hex = f"04{point[0]:x}{point[1]:x}"
        if len(publickey_hex) < 130:
            publickey_hex = publickey_hex[:2] + "0" + publickey_hex[2:]
        return publickey_hex

    def compress_point(self, publickey_Hex: str) -> str:
        if publickey_Hex[0:2] != '04':
            raise ValueError('Invalid Public Key')
        x = int(publickey_Hex[2:66], 16)
        y = int(publickey_Hex[66:], 16)

        if y & 1 == 0:
            publickey_Hex = '02' + format(x, '064x')
        else:
            publickey_Hex = '03' + format(x, '064x')
        return publickey_Hex

    
    """ ------------------- การคำนวณหลัก สร้างลายเซ็นและตรวจสอบ ECDSA ------------------- """
    
    def signing(self, private_key, message):
        z = message
        #k = 42854675228720239947134362876390869888553449708741430898694136287991817016610
        k = getrandbits(256)
        r, s = 0, 0
        while r == 0 or s == 0:
            point = self.multiply(k)
            k_inv = self.modinv(k, self.N)
            r = point[0] % self.N
            s = ((z + r * private_key) * k_inv) % self.N
        return (r, s)

    def verify(self, publickey, message, Signature):
        m = message
        r, s = Signature

        w = self.modinv(s, self.N)
        u1 = (m * w) % self.N
        u2 = (r * w) % self.N

        point1 = self.multiply(u1)
        point2 = self.multiply(u2, publickey)

        point = self.add(point1, point2)
        x = point[0] % self.N
        return x == r

    def to_der_format(self, Signature):
        r, s = Signature
        rb = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big', signed=False)
        sb = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big', signed=False)

        der_r = b'\x02' + len(rb).to_bytes(1, byteorder='big', signed=False) + rb
        der_s = b'\x02' + len(sb).to_bytes(1, byteorder='big', signed=False) + sb
        der_sig = b'\x30' + (len(der_r) + len(der_s)).to_bytes(1, byteorder='big', signed=False) + der_r + der_s
        return der_sig.hex()


if __name__ == "__main__":
    curve = ECSecp256k1()
    private_key = getrandbits(256)
    #private_key = 111798668807017442629247557499629816624858299873427551140682199544191852692645
    print("[H] Private key:", hex(private_key)[2:])
    print("Private key:", private_key)
    message = 67190017246757783140308448604179518505030850719375738244213419124624541387587

    P = curve.multiply(private_key)
    print("\nKey Point", P)

    publickey_Hex = curve.publickey(private_key)
    print("[U] Public Key:", publickey_Hex)

    compress = curve.compress_point(publickey_Hex)
    print("[C] Public Key:", compress)

    sign = curve.signing(private_key, message)
    print("\nSignature", sign)

    der = curve.to_der_format(sign)
    print("Der format:", der)

    isValid = curve.verify(P, message, sign)
    if isValid:
        print("Signature is valid")
    else:
        print("Signature is invalid")
