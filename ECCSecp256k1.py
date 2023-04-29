import random
from hashlib import sha256

# Secp256k1.py
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
        slope = ((3 * point["x"] ** 2) * self.modinv((2 * point["y"]))) % self.P  # using modular inverse to perform "division"
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
        for Fbin_prv in binary[1:]:
            current = self.double(current)
            if Fbin_prv == "1":
                current = self.add(current, point)
        return current

    def create_full_public_key(self, k) -> str:
        key = bytes.fromhex(k)
        coordinates = self.multiply(int.from_bytes(key, 'big'))
        x = hex(coordinates["x"])[2:]; y = hex(coordinates["y"])[2:]
        return "04" + x + y

    def create_compress_public_key(self, public_key) -> str:
        if public_key[0:2] != '04':
            raise ValueError('Invalid Public Key')
        x = int(public_key[2:66], 16)
        y = int(public_key[66:], 16)

        if (y % 2) == 0:
            public_key = '02' + format(x, '064x')
        else:
            public_key = '03' + format(x, '064x')
        return public_key

    def full_public_key(self, k):
        return self.create_full_public_key(k)

    def compress_public_key(self, k):
        return self.create_compress_public_key(k)

    def VerifyingSig(self, public_key, Tx_hash, signature):
        return self.proof_signature(public_key, Tx_hash, signature)

    def proof_signature(self, public_key, Tx_hash, signature):
        # Convert signature to bytes
        signature_bytes = bytes.fromhex(signature)

        # Parse DER headers
        r_pos = 4
        r_len = signature_bytes[3]
        s_pos = r_pos + r_len + 2
        s_len = signature_bytes[s_pos - 1]
        r_bytes = signature_bytes[r_pos:r_pos + r_len]
        s_bytes = signature_bytes[s_pos:s_pos + s_len]

        # Convert r and s to integers
        r = int.from_bytes(r_bytes, byteorder='big', signed=False)
        s = int.from_bytes(s_bytes, byteorder='big', signed=False)

        # Compute the Tx_hash hash
        hash_tx = sha256(Tx_hash.encode()).digest()
        e = int.from_bytes(hash_tx, byteorder="big")

        # Verify signature
        w = self.modinv(s)
        u1 = (e * w) % self.N
        u2 = (r * w) % self.N
        x, y = self.add(self.multiply(u1), self.multiply(u2, public_key))
        if (r % self.N) == (x % self.N):
            return True
        else:
            return False

    def Signature(self, Tx_hash, private_key) -> str:
        # generate a random integer k between 1 and n-1
        k = random.randint(1, self.N-1)
        # compute the public key point R = k * G
        R = self.multiply(k)
        # compute r = x-coordinate of R mod n
        r = R["x"] % self.N
        if r == 0:
            # if r == 0, choose another k
            return self.Signature(Tx_hash, private_key)
        # compute the Tx_hash hash
        hash_tx = sha256(Tx_hash.encode()).digest()
        # convert the hash to an integer
        e = int.from_bytes(hash_tx, byteorder="big")
        # compute s = (e + d*r) * inv(k) mod n
        d = int(private_key, 16)
        k_inv = self.modinv(k)
        s = (e + d*r) * k_inv % self.N
        if s == 0:
            # if s == 0, choose another k
            return self.Signature(Tx_hash, private_key)
        # return the signature (r, s)
        return (r, s)

    def Signing(self, Tx_hash, private_key):
        signature = self.Signature(Tx_hash, private_key)
        return self.DERencode(signature)

    def DERencode(self, Signature) -> str:
        """ Make to the signature in DER format """
        r, s = Signature
        # Convert r and s to bytes
        rb = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big', signed=False)
        sb = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big', signed=False)
        # Add DER headers to r and s
        der_r = b'\x02' + len(rb).to_bytes(1, byteorder='big', signed=False) + rb
        der_s = b'\x02' + len(sb).to_bytes(1, byteorder='big', signed=False) + sb
        # Concatenate DER headers
        der_sig = b'\x30' + (len(der_r) + len(der_s)).to_bytes(1, byteorder='big', signed=False) + der_r + der_s
        return der_sig.hex()


class SchnorrSignature:
    def __init__(self):
        self.curve = Secp256k1()

    def _calculate_challenge(self, message, R, public_key):
        h = sha256()
        h.update(R.encode('utf-8'))
        h.update(public_key.encode('utf-8'))
        h.update(message.encode('utf-8'))
        return int(h.hexdigest(), 16)

    def sign(self, message, private_key):
        k = random.randint(1, self.curve.N - 1)
        R = self.curve.multiply(k)
        e = self._calculate_challenge(message, R['x'], self.curve.compress_key(self.curve.G))
        s = (k - e * private_key) % self.curve.N
        return (R['x'], s)

    def verify(self, message, signature, public_key):
        R, s = signature
        e = self._calculate_challenge(message, str(R), public_key)
        P = self.curve.decompress_key(public_key)
        R = self.curve.add(self.curve.multiply(s, self.curve.G), self.curve.multiply(e, P))
        return R['x'] == signature[0]


class ECDSA:
    def __init__(self, secp256k1):
        self.curve = secp256k1

    def sign(self, message, private_key):
        z = int(sha256(message.encode()).hexdigest(), 16)
        k = random.randint(1, self.curve.N-1)
        R = self.curve.multiply(k)
        r = R['x'] % self.curve.N
        s = (self.curve.modinv(k) * (z + r * private_key)) % self.curve.N
        if s > self.curve.N / 2:
            s = self.curve.N - s
        return (r, s)

    def verify(self, message, signature, public_key):
        z = int(sha256(message.encode()).hexdigest(), 16)
        r, s = signature
        if not (0 < r < self.curve.N and 0 < s < self.curve.N):
            return False
        w = self.curve.modinv(s)
        u1 = (z * w) % self.curve.N
        u2 = (r * w) % self.curve.N
        R = self.curve.add(self.curve.multiply(u1), self.curve.multiply(u2, public_key))
        if R is None:
            return False
        return r == R['x'] % self.curve.N
def main():
    secp256k1 = Secp256k1()
    ecdsa = ECDSA(secp256k1)

    message = "Hello, world!"
    private_key = 12345
    public_key = secp256k1.multiply(private_key)

    signature = ecdsa.sign(message, private_key)
    print("Signature:", signature)

    valid = ecdsa.verify(message, signature, public_key)
    print("Valid:", valid)

    # --------------------------------------------------------
    curve = Secp256k1()
    private_key = "e38b1a0e3169055bbec35266002ee43519a545dd30c6315942ce82da60b5853d"
    k = int(private_key, 16)
    public_key = curve.multiply(k)

    x = hex(public_key["x"])[2:]
    y = hex(public_key["y"])[2:]

    Int_key = x, y
    print(Int_key)

    print(f"X coordinate: {x}")
    print(f"Y coordinate: {y}")

    full_pub = "04" + x + y
    print(f'\nFull Public Key: {full_pub}')

    publiceky = curve.full_public_key(private_key)

    compress_key = curve.compress_public_key(publiceky)
    print(f'Compress Puclic key: {compress_key}')
    Tx_hash = "9520c60e59221004ab03c16266c3d06dcd680ce44ed8ba55ef44e76c3561229b"
    print(f'Message: {Tx_hash}')
    sig = curve.Signing(Tx_hash, private_key)
    print("Digital Signatures: ", sig)

    #check_sig = curve.VerifyingSig(publiceky, Tx_hash, sig)
    """
    valid_signature = curve.VerifyingSig(Int_key, Tx_hash, sig)
    if valid_signature:
        print("Signature is valid!")
    else:
        print("Signature is invalid.")
    """

if __name__=="__main__":
    main()

