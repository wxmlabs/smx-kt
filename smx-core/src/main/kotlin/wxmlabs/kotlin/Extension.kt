package wxmlabs.kotlin

private val HEX_DICT = "0123456789abcdef"

fun Byte.toHexString(): String {
    val n = this.toInt()
    return "${HEX_DICT[n shr 4 and 0x0f]}${HEX_DICT[n and 0x0f]}"
}

fun ByteArray.toHexString(style: HexStringStyle = DefaultHexStringStyle()): String {
    val sb = StringBuilder()
    this.forEachIndexed { i, b ->
        style.appendTo(sb, b.toHexString(), i)
    }
    return sb.toString()
}

interface HexStringStyle {
    fun appendTo(builder: StringBuilder, byteHexString: String, byteIndex: Int)
}

class DefaultHexStringStyle : HexStringStyle {
    override fun appendTo(builder: StringBuilder, byteHexString: String, byteIndex: Int) {
        builder.append(byteHexString)
    }
}

fun Long.toByteArray(): ByteArray { // 8Bytes
    return byteArrayOf(
            this.ushr(56).toByte()
            , this.ushr(48).toByte()
            , this.ushr(40).toByte()
            , this.ushr(32).toByte()
            , this.ushr(24).toByte()
            , this.ushr(16).toByte()
            , this.ushr(8).toByte()
            , this.toByte()
    )
}