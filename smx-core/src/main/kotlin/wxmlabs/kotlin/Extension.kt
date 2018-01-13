package wxmlabs.kotlin

private val HEX_DICT = "0123456789abcdef"

fun Byte.toHexString(): String {
    val n = this.toInt()
    return "${HEX_DICT[n shr 4 and 0x0f]}${HEX_DICT[n and 0x0f]}"
}

fun ByteArray.toHexString(style: HexStringStyle): String {
    val sb = StringBuilder()
    this.forEachIndexed { i, b ->
        style.appendTo(sb, b.toHexString(), i)
    }
    style.reset()
    return sb.toString()
}

fun ByteArray.toHexString(): String {
    return this.toHexString(DefaultHexStringStyle())
}

interface HexStringStyle {
    /**
     * 在每个字节转换为十六进制字符串时调用。
     *
     * @param builder 内置的StringBuilder，可用于改变输出样式。
     * @param byteHexString 当前字节的十六进制字符串
     * @param byteIndex 当前字节在ByteArray中的索引
     */
    fun appendTo(builder: StringBuilder, byteHexString: String, byteIndex: Int)

    /**
     * 重置Style对象。当HexString构建结束时调用。
     */
    fun reset()
}

private class DefaultHexStringStyle : HexStringStyle {
    override fun appendTo(builder: StringBuilder, byteHexString: String, byteIndex: Int) {
        builder.append(byteHexString)
    }

    override fun reset() {}
}

fun Int.toByteArray(): ByteArray { // 4Bytes
    return byteArrayOf(
        this.ushr(24).toByte(),
        this.ushr(16).toByte(),
        this.ushr(8).toByte(),
        this.toByte()
    )
}

fun intFromBytes(b0: Byte, b1: Byte, b2: Byte, b3: Byte): Int {
    return (b0.toInt().and(0xff).shl(24) or
        b1.toInt().and(0xff).shl(16) or
        b2.toInt().and(0xff).shl(8) or
        b3.toInt().and(0xff))
}

fun Long.toByteArray(): ByteArray { // 8Bytes
    return byteArrayOf(
        (this ushr 56).toByte(),
        (this ushr 48).toByte(),
        (this ushr 40).toByte(),
        (this ushr 32).toByte(),
        (this ushr 24).toByte(),
        (this ushr 16).toByte(),
        (this ushr 8).toByte(),
        this.toByte()
    )
}
