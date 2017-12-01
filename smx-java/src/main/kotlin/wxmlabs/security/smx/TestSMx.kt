package wxmlabs.security.smx

import wxmlabs.kotlin.*

fun testDigest() {
    SMxProperties.debug = true
    val message = byteArrayOf(0x61, 0x62, 0x63)
    val sm3Digest = SM3.digest(message)
    val expect = wordArrayOf(0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b.toWord(), 0xdc10e4e2.toWord(), 0x4167c487, 0x5cf2f7a2, 0x297da02b, 0x8f4ba8e0.toWord()).toByteArray()
    println("digest: \n${sm3Digest.toHexString(SM3.wordHexStyle)}")
    println("expected digest: \n${expect.toHexString(SM3.wordHexStyle)}")

    for (i in 0 until expect.size) {
        if (sm3Digest[i] != expect[i]) {
            println("error from byte index $i")
            break
        }
    }
}

fun main(args: Array<String>) {
    testDigest()
}