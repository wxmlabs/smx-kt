package wxmlabs.security.smx

import kotlin.test.Test
import kotlin.test.asserter

@Test
fun testDigest() {
    val sm3Digest = SM3.digest(byteArrayOf(0x61, 0x62, 0x63))
    val expect = wordArrayOf(0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b.toWord(), 0xdc10e4e2.toWord(), 0x4167c487, 0x5cf2f7a2, 0x297da02b, 0x8f4ba8e0.toWord()).toByteArray()
    asserter.assertSame("SM3 Message Digest", sm3Digest, expect)
}