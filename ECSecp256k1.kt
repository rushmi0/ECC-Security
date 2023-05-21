import java.math.BigInteger
import java.security.SecureRandom

/*
* https://www.secg.org/sec2-v2.pdf
* */

class ECSecp256k1 {

    // * Secp256k1 curve
    private val A = BigInteger.ZERO
    private val B = BigInteger.valueOf(7)
    private val P = BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")
    private val N = BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337")
    private val G = Point(
        BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
        BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424")
    )

    data class Point(val x: BigInteger, val y: BigInteger)


    /*  ------------------- การคำนวณหลัก Elliptic Curve cryptography -------------------  */

    private fun modinv(A: BigInteger, N: BigInteger = P): BigInteger {
        return A.modInverse(N)
    }

    private fun double(point: Point): Point {
        val (x, y) = point
        val lam_numer = (BigInteger.valueOf(3) * x * x + A) % P
        val lam_denom = (BigInteger.valueOf(2) * y) % P
        val lam = (lam_numer * modinv(lam_denom)) % P

        val xR = (lam * lam - BigInteger.valueOf(2) * x) % P
        val yR = (lam * (x - xR) - y) % P
        return Point(xR, yR)
    }

    private fun add(point1: Point, point2: Point): Point {
        if (point1 == point2) {
            return double(point1)
        }
        val (x1, y1) = point1
        val (x2, y2) = point2

        val m = ((y2 - y1) * modinv(x2 - x1)) % P
        val xR = (m * m - x1 - x2) % P
        val yR = (m * (x1 - xR) - y1) % P
        return Point(xR, yR)
    }

    fun multiply(k: BigInteger, point: Point? = null): Point {
        val current = point ?: G
        val binary = k.toString(2)
        var currentPoint = current
        for (i in 1 until binary.length) {
            currentPoint = double(currentPoint)
            if (binary[i] == '1') {
                currentPoint = add(currentPoint, current)
            }
        }
        return currentPoint
    }


    /*  ------------------- ส่วนขยาย -------------------  */

    fun publicKey(k: BigInteger): String {
        val point = multiply(k)
        var publickey = "04${point.x.toString(16)}${point.y.toString(16)}"

        if (publickey.length < 130) {
            publickey = publickey.substring(0, 2) + "0" + publickey.substring(2)
        }
        return publickey
    }

    fun compressPoint(publicKeyHex: String): String {
        if (publicKeyHex.substring(0, 2) != "04") {
            throw IllegalArgumentException("Invalid Public Key")
        }
        val x = BigInteger(publicKeyHex.substring(2, 66), 16)
        val y = BigInteger(publicKeyHex.substring(66), 16)

        val compressedKey = if (y and BigInteger.ONE == BigInteger.ZERO) {
            "02" + x.toString(16).padStart(64, '0')
        } else {
            "03" + x.toString(16).padStart(64, '0')
        }
        return compressedKey
    }


    /*  ------------------- การคำนวณหลัก สร้างลายเซ็นและตรวจสอบ ECDSA -------------------  */

    fun signing(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {
        val z = message
        //val k = BigInteger("42854675228720239947134362876390869888553449708741430898694136287991817016610")
        val k = BigInteger(256, SecureRandom())
        var r = BigInteger.ZERO
        var s = BigInteger.ZERO
        while (r == BigInteger.ZERO || s == BigInteger.ZERO) {
            val point = multiply(k)
            val kInv = modinv(k, N)
            r = point.x % N
            s = ((z + r * privateKey) * kInv) % N
        }
        return Pair(r, s)
    }

    fun verify(publicKey: Point, message: BigInteger, signature: Pair<BigInteger, BigInteger>): Boolean {
        val (r, s) = signature

        val w = modinv(s, N)
        val u1 = (message * w) % N
        val u2 = (r * w) % N

        val point1 = multiply(u1)
        val point2 = multiply(u2, publicKey)

        val point = add(point1, point2)
        val x = point.x % N
        return x == r
    }

    fun toDERFormat(signature: Pair<BigInteger, BigInteger>): String {
        val (r, s) = signature
        val rb = r.toByteArray()
        val sb = s.toByteArray()

        val der_r = byteArrayOf(0x02.toByte()) + rb.size.toByte() + rb
        val der_s = byteArrayOf(0x02.toByte()) + sb.size.toByte() + sb
        val der_sig = byteArrayOf(0x30.toByte()) + (der_r.size + der_s.size).toByte() + der_r + der_s
        return der_sig.joinToString("") { String.format("%02x", it) }
    }

}

fun main() {
    val curve = ECSecp256k1()

    val privateKey = BigInteger(256, SecureRandom())
    //val privateKey = BigInteger("111798668807017442629247557499629816624858299873427551140682199544191852692645")
    println("[H] Private key: ${privateKey.toString(16)}")
    println("Private key: $privateKey")

    val message = BigInteger("67190017246757783140308448604179518505030850719375738244213419124624541387587")

    val P = curve.multiply(privateKey)
    println("\nKey Point: $P")

    val publicKeyHex = curve.publicKey(privateKey)
    println("[U] Public Key: $publicKeyHex")

    val compress = curve.compressPoint(publicKeyHex)
    println("[C] Public Key: $compress")

    val sign = curve.signing(privateKey, message)
    println("\nSignature: $sign")

    val der = curve.toDERFormat(sign)
    println("Der format: $der")

    val isValid = curve.verify(P, message, sign)
    if (isValid) {
        println("Signature is valid")
    } else {
        println("Signature is invalid")
    }

}


