package wxmlabs.security.smx


val dict = "0123456789abcdef"

fun ByteArray.toHexString(): String {
    var s = ""
    this.forEach { byte: Byte ->
        s += byte.toInt() shr 4 and 0x0f
        s += byte.toInt() and 0x0f
    }
    return s
}

fun testDigest() {
    val sm3Digest = SM3.digest(byteArrayOf(0x61, 0x62, 0x63))
    val expect = wordArrayOf(0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b.toWord(), 0xdc10e4e2.toWord(), 0x4167c487, 0x5cf2f7a2, 0x297da02b, 0x8f4ba8e0.toWord()).toByteArray()
    println(sm3Digest.toHexString())
    println(expect.toHexString())
    expect.forEachIndexed { i, byte ->
        if (expect[i] != sm3Digest[i]) println(i)
    }
}

fun main(args: Array<String>) {
    testDigest()
}