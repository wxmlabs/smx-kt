package wxmlabs.security.smx

import kotlin.test.Test
import kotlin.test.asserter

@Suppress("unused")
class SM3Test {
    @Test
    fun test24bitsSM3Digest() {
        debug = true
        val digest = SM3.digest(byteArrayOf(0x61, 0x62, 0x63))
        val expect = wordArrayOf(0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b.toWord(), 0xdc10e4e2.toWord(), 0x4167c487, 0x5cf2f7a2, 0x297da02b, 0x8f4ba8e0.toWord()).toByteArray()
        asserter.assertTrue("SM3 Message Digest 24bits check.", digest.contentEquals(expect))
    }

    @Test
    fun test512bitsSM3Digest() {
        debug = true
        val digest = SM3.digest(wordArrayOf(
            0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364,
            0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364, 0x61626364)
            .toByteArray())
        val expect = wordArrayOf(0xdebe9ff9.toWord(), 0x2275b8a1, 0x38604889, 0xc18e5a4d.toWord(), 0x6fdb70e5, 0x387e5765, 0x293dcba3, 0x9c0c5732.toWord()).toByteArray()
        asserter.assertTrue("SM3 Message Digest 512bits check.", digest.contentEquals(expect))
    }

    // TODO 使用代码检查每一个计算细节
}
