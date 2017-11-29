package wxmlabs.security.smx

/**
 *  SM3密码杂凑算法
 *  （PS：杂凑算法又称为“消息摘要（Message Digest）算法”）
 */
class SM3 {}
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
 *      m'：填充后的消息
 *      mod：模运算
 *      ∧：32比特与运算
 *      ∨：32比特或运算
 *      ⊕：32比特异或运算
 *      ¬：32比特非运算
 *      +：mod232算术加运算
 *      ≪k：循环左移k比特运算
 *      ←：左向赋值运算符
 */

/**
 *  4. 常数与函数
 */
/**
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
    } else if (j in 16..32) {
        0x7a879d8a
    }
    throw IllegalArgumentException("j must in 0..32")
}

/**
 *  4.3 布尔函数
 *                X ⊕ Y ⊕ Z                         0 ≤ j ≤ 15
 *  FFj(X,Y,Z) = {
 *                (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)       16 ≤ j ≤ 63
 *
 *                X ⊕ Y ⊕ Z                         0 ≤ j ≤ 15
 *  GGj(X,Y,Z) = {
 *                (X ∧ Y ) ∨ ( ¬X∧ Z)               16 ≤ j ≤ 63
 */
fun FF(X: Word, Y: Word, Z: Word): Any {
    return { j: Int ->

    }
}

fun GG(X: Word, Y: Word, Z: Word): Any {
    return { j: Int ->

    }
}

/**
 *  4.4 置换函数
 *  P0(X) = X ⊕ (X ≪ 9) ⊕ (X ≪ 17)
 *  P1(X) = X ⊕ (X ≪ 15) ⊕ (X ≪ 23)
 *  式中X为字。
 */
fun P0(X: Word): Any {
    return 0
}

fun P1(X: Word): Any {
    return 0
}

fun SM3.digest(plaintext: ByteArray): ByteArray {
    val digist: ByteArray = byteArrayOf(0)
    return digist
}