package wxmlabs.security.smx

import java.security.MessageDigestSpi

internal class SM3MessageDigest : MessageDigestSpi() {
    private val sm3 = SM3()
    override fun engineReset() {
        sm3.reset()
    }

    override fun engineUpdate(input: Byte) {
        sm3.update(input)
    }

    override fun engineUpdate(input: ByteArray?, offset: Int, len: Int) {
        if (input != null) {
            sm3.update(input, offset, len)
        }
    }

    override fun engineDigest(): ByteArray {
        return sm3.digest()
    }
}
