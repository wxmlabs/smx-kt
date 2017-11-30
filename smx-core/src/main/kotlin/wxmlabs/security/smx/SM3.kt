package wxmlabs.security.smx

/**
 *  SM3密码杂凑算法
 *  （PS：杂凑算法又称为“消息摘要（Message Digest）算法”）
 */

/**
 *  1. 范围
 *      本文本规定了SM3密码杂凑算法的计算方法和计算步骤，并给出了运算示例。
 *      本文本适用于商用密码应用中的数字签名和验证、消息认证码的生成与验证以及随机数的生成，可满足多种密码应用的安全需求。
 *  同时本文本还可为安全产品生产商提供产品和技术的标准定位以及标准化的参考，提高安全产品的可信性与互操作性。
 */

/**
 *  2. 术语及定义
 *  2.1
 *      比特串  bit string
 *      由0和1组成的二进制数字序列。
 *  2.2
 *      大端  big-endian
 *      数据在内存中的一种表示格式，规定左边为高有效位，右边为低有效位。数的高阶字节放在存储器的低位地址，数的低阶字节
 *  放在存储器的高位地址。
 *  2.3
 *      消息 message
 *      任意长度的比特串。本文本中消息作为杂凑算法的输入数据。
 *  2.4
 *      杂凑值  hash value
 *      杂凑算法作用用途消息后输出的特定长度的比特串。本文本中杂凑值长度为256比特。
 *  2.5
 *      字  word
 *      长度为32的比特串。
 */

typealias Word = Int
typealias WordArray = IntArray
fun wordArrayOf(vararg elements: Word): WordArray {
    val wordArray = WordArray(elements.size)
    elements.forEachIndexed { idx, word ->
        wordArray[idx] = word
    }
    return wordArray
}

fun Long.toWord(): Word {
    return this.toInt()
}

fun Int.toByteArray(): ByteArray {
    return byteArrayOf(
            this.ushr(24).toByte()
            , this.ushr(16).toByte()
            , this.ushr(8).toByte()
            , this.toByte()
    )
}

/**
 *  3. 符号
 *      下列符号适用于本文本。
 *      ABCDEFGH：8个字寄存器或它们的值的串联
 *      B(i)：第i个消息分组
 *      CF：压缩函数
 *      FFj：布尔函数，随j变化取不同的表达式
 *      GGj：布尔函数，随j变化取不同的表达式
 *      IV：初始值，用于确定压缩函数寄存器的初态
 *      P0：压缩函数中的置换函数
 *      P1：消息扩展中的置换函数
 *      Tj：常量，随j的变化取不同的值
 *      m：消息
 *      m′：填充后的消息
 *      mod：模运算
 *      ∧：32比特与运算
 *      ∨：32比特或运算
 *      ⊕：32比特异或运算
 *      ¬：32比特非运算
 *      +：mod232算术加运算
 *      ≪k：循环左移k比特运算
 *      ←：左向赋值运算符
 */

/** 循环左移。Ring shifts this value light by [bits]. */
infix fun Word.rshl(bitCount: Int): Word { // ring shift left
    return this.shl(bitCount) or this.ushr(32 - bitCount)
}

/**
 *  4. 常数与函数
 *  4.1 初始值
 *  IV ＝ 7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
 */
val IV: WordArray = wordArrayOf(0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600.toWord(), 0xa96f30bc.toWord(), 0x163138aa, 0xe38dee4d.toWord(), 0xb0fb0e4e.toWord())

/**
 *  4.2 常量
 *        79cc4519 0 ≤ j ≤ 15
 *  Tj ＝｛
 *        7a879d8a 16 ≤ j ≤ 63
 */
val T: (Int) -> Word = { j ->
    if (j in 0..15) {
        0x79cc4519
    } else if (j in 16..63) {
        0x7a879d8a
    }
    throw IllegalArgumentException("j must in 0..63")
}

/**
 *  4.3 布尔函数
 *                X ⊕ Y ⊕ Z                         0 ≤ j ≤ 15
 *  FFj(X,Y,Z) = {
 *                (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)       16 ≤ j ≤ 63
 *
 *                X ⊕ Y ⊕ Z                         0 ≤ j ≤ 15
 *  GGj(X,Y,Z) = {
 *                (X ∧ Y) ∨ (¬X ∧ Z)               16 ≤ j ≤ 63
 */
fun FF(X: Word, Y: Word, Z: Word): Any {
    return { j: Int ->
        if (j in 0..15) {
            X xor Y xor Z
        } else if (j in 16..63) {
            (X and Y) or (X and Z) or (Y and Z)
        }
        throw IllegalArgumentException("j must in 0..63")
    }
}

fun GG(X: Word, Y: Word, Z: Word): Any {
    return { j: Int ->
        if (j in 0..15) {
            X xor Y xor Z
        } else if (j in 16..63) {
            (X and Y) or (X.inv() and Z)
        }
        throw IllegalArgumentException("j must in 0..63")
    }
}

/**
 *  4.4 置换函数
 *  P0(X) = X ⊕ (X ≪ 9) ⊕ (X ≪ 17)
 *  P1(X) = X ⊕ (X ≪ 15) ⊕ (X ≪ 23)
 *  式中X为字。
 */
fun P0(X: Word): Any {
    return X xor (X rshl 9) xor (X rshl 17)
}

fun P1(X: Word): Any {
    return X xor (X rshl 15) xor (X rshl 23)
}

/**
 * 5. 算法描述
 * 5.1 概述
 * 对长度为l(l < 2⁶⁴) 比特的消息m,SM3杂凑算法经过填充和迭代压缩,生成杂凑值,杂凑值长度 为256比特。
 */
val bitLength = 256

/**
 * 5.2 填充
 * 假设消息m的长度为l比特。首先将比特“1”添加到消息的末尾,再添加k个“0”,k是满足l+1+k≡448mod512的最小的非负整数。然后再添加一个64位比特串,该比特串是长度l的二进制表示。填充后的消息m′的比特长度为512的倍数。
 * 例如:
 * 对消息01100001 01100010 01100011,其长度l=24,经填充得到比特串:
 *            |24比特                   |1比特|423比特    |64比特
 *            01100001 01100010 01100011 1   00 · · · 00 00 · · · 011000
 *                                                     l的二进制表示
 */
fun padding(message: ByteArray): ByteArray { // 可优化。在最后的运算过程中，最后计算padding。
    val byteLength = message.size
    val remLength = byteLength.rem(64)
    return if (remLength > 56) {
        val zeroByteArray = ByteArray(123 - remLength)
        byteArrayOf(*message, 0x80.toByte(), *zeroByteArray, *byteLength.toByteArray())
    } else {
        val zeroByteArray = ByteArray(59 - remLength)
        byteArrayOf(*message, 0x80.toByte(), *zeroByteArray, *byteLength.toByteArray())
    }
}

/**
 * 5.3 迭代压缩 5.3.1 迭代过程
 * 将填充后的消息m′按512比特进行分组:m′=B(0)B(1) · · · B(n−1)其中n=(l+k+65)/512。
 * 对m′按下列方式迭代:
 * FOR i=0 TO n-1
 *     V(i+1)=CF(V(i),B(i))
 * ENDFOR
 * 其中CF是压缩函数,V(0)为256比特初始值IV,B(i)为填充后的消息分组,迭代压缩的结果为V(n)。
 */
fun CF(Vi: WordArray, Bi: ByteArray): WordArray {
    val Viplus1 = WordArray(8)
    return Viplus1
}

class SM3 {
    fun update(plaintext: ByteArray): Int {
        return 0
    }

    fun doFinal(plaintext: ByteArray): ByteArray {
        val digist: ByteArray = byteArrayOf(0)
        return digist
    }
}
