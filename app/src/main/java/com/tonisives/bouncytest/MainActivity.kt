package com.tonisives.bouncytest

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.tonisives.bouncytest.R
import com.highmobility.value.Bytes
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {
    val params = ECNamedCurveTable.getParameterSpec("secp256r1")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        rawBytesToPublicKey()
        rawBytesToPrivateKey()
        createHmac()

        signAndVerify()
    }

    fun rawBytesToPublicKey() : ECPublicKey {
        val rawPublicKey =
            Bytes("046ce12c7abdff053198ede88abcd3c31cee00ae598ba46a1bf961c909feb3b01e531faf566baf9b4bdb14734bf0adc3561813bf9f2f40fc26ab2bfecfd64f0242")

        val keySpec =
            ECPublicKeySpec(params.curve.decodePoint(rawPublicKey.byteArray), params)

        val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())
        val javaPublicKey = keyFactory.generatePublic(keySpec) as ECPublicKey

        // convert back to bytes
        val publicPoint = javaPublicKey.w
        val convertedBack = Bytes(65)
        convertedBack.set(0, 0x04)
        // note the BigInteger can sometimes be 31 bytes, when 0x00 need to be prepended to make it 32
        // bytes long
        convertedBack.set(1, publicPoint.affineX.toBytes(32))
        convertedBack.set(33, publicPoint.affineY.toBytes(32))

        println("rawPublicKey: $rawPublicKey")
        println("convertedBack: $convertedBack")
        require(rawPublicKey == convertedBack)

        return javaPublicKey
    }

    fun rawBytesToPrivateKey() : ECPrivateKey{
        val rawPrivateKey =
            Bytes("6cabc1a859649db758e925bc3553f14f4e3065deb3c6cf7ef831cb14a69355a3")

        val d = BigInteger(1, rawPrivateKey.byteArray)
        val curveSpec = ECParameterSpec(params.curve, params.g, params.n, params.h)
        val privateKeySpec = ECPrivateKeySpec(d, curveSpec)

        val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())
        val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

        // assure the d value is always 32 bytes long
        val convertedBack = privateKey.d.toBytes(32)
        println("rawPrivateKey: $rawPrivateKey")
        println("convertedBack: $convertedBack")
        require(rawPrivateKey == convertedBack)

        return privateKey
    }

    // prepend 00 if numBytes bigger. remove from beginning if numBytes smaller
    fun BigInteger.toBytes(numBytes: Int): Bytes {
        val bytes = ByteArray(numBytes)
        val biBytes = this.toByteArray()
        val start = if (biBytes.size == numBytes + 1) 1 else 0
        val length = biBytes.size.coerceAtMost(numBytes)
        System.arraycopy(biBytes, start, bytes, numBytes - length, length)
        return Bytes(bytes)
    }

    fun createHmac() {
        val sharedSecretKey = byteArrayOf(0, 1, 2)
        val message = byteArrayOf(0, 1, 2)

        val key: SecretKey = SecretKeySpec(sharedSecretKey, "HmacSHA256")
        val mac: Mac = Mac.getInstance("HmacSHA256", BouncyCastleProvider())
        mac.init(key)
        val hmac = mac.doFinal(message)

        println("hmac ${Bytes(hmac)}")
    }

    fun signAndVerify() {
        val publicKey = rawBytesToPublicKey()
        val privateKey = rawBytesToPrivateKey()

        val message = Bytes("aabb")
        val signer = Signature.getInstance("SHA256withPLAIN-ECDSA", BouncyCastleProvider())
        signer.initSign(privateKey)
        signer.update(message.byteArray)
        val signature = signer.sign()

        println("signature: ${Bytes(signature)}")
        val verifier = Signature.getInstance("SHA256withPLAIN-ECDSA", BouncyCastleProvider())
        verifier.initVerify(publicKey)
        verifier.update(message.byteArray)
        val result = verifier.verify(signature)
        require(result == true)
    }
}