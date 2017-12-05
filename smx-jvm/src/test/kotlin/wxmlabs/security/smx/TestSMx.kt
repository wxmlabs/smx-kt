package wxmlabs.security.smx

import wxmlabs.kotlin.toHexString
import java.security.MessageDigest
import kotlin.math.min

fun check(oneByteArray: ByteArray, otherByteArray: ByteArray) {
    var isEq = true
    var len = min(oneByteArray.size, otherByteArray.size)
    for (i in 0 until len) {
        if (oneByteArray[i] != otherByteArray[i]) {
            println("error from byte index $i")
            isEq = false
            break
        }
    }
    if (oneByteArray.size != otherByteArray.size) {
        println("error from byte index $len")
        isEq = false
    }
    if (isEq)
        println("###Fine!")
}

fun testDigest(message: ByteArray, expect: ByteArray) {
    val sm3Digest = SM3.digest(message)
    println("digest: \n${sm3Digest.toHexString(SM3.wordHexStyle)}")
    println("expected digest: \n${expect.toHexString(SM3.wordHexStyle)}")

    check(sm3Digest, expect)
}

fun testDigestProvider(message: ByteArray, expect: ByteArray) {
    val sm3 = MessageDigest.getInstance("SM3")
    sm3.update(message)
    val sm3Digest = sm3.digest()
    println("digest: \n${sm3Digest.toHexString(SM3.wordHexStyle)}")
    println("expected digest: \n${expect.toHexString(SM3.wordHexStyle)}")

    check(sm3Digest, expect)
}

fun main(args: Array<String>) {
    val testData = arrayOf(
            arrayOf(byteArrayOf(0x61, 0x62, 0x63),
                    wordArrayOf(0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b.toWord(), 0xdc10e4e2.toWord(), 0x4167c487, 0x5cf2f7a2, 0x297da02b, 0x8f4ba8e0.toWord()).toByteArray()),
            arrayOf(wordArrayOf(
                    0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364,
                    0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364).toByteArray(),
                    wordArrayOf(
                            0xdebe9ff9.toWord(), 0x2275b8a1, 0x38604889, 0xc18e5a4d.toWord(), 0x6fdb70e5, 0x387e5765, 0x293dcba3, 0x9c0c5732.toWord()).toByteArray())
    )
    val separation = "========"
    SMxProperties.debug = true
    println(separation)
    testDigest(testData[0][0], testData[0][1])
    println(separation)
    testDigest(testData[1][0], testData[1][1])

    SMxProperties.debug = false
    SMxProvider.register()
    println(separation)
    testDigestProvider(testData[0][0], testData[0][1])
    println(separation)
    testDigestProvider(testData[1][0], testData[1][1])
}