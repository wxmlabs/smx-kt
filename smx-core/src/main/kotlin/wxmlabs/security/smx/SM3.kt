@file:Suppress("LocalVariableName", "PrivatePropertyName", "FunctionName")

package wxmlabs.security.smx

import wxmlabs.kotlin.*

/**
 *  SM3密码杂凑算法
 *  （PS：杂凑算法又称为“消息摘要（Message Digest）算法”）
 */
/**-
 *  1. 范围
 *      本文本规定了SM3密码杂凑算法的计算方法和计算步骤，并给出了运算示例。
 *      本文本适用于商用密码应用中的数字签名和验证、消息认证码的生成与验证以及随机数的生成，可满足多种密码应用的安全需求。
 *  同时本文本还可为安全产品生产商提供产品和技术的标准定位以及标准化的参考，提高安全产品的可信性与互操作性。
 */

/**-
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

/** 循环左移。Ring shifts this value light by [bitCount]. */
infix fun Word.rshl(bitCount: Int): Word { // ring shift left
    return this.shl(bitCount) or this.ushr(32 - bitCount)
}

fun WordArray.toByteArray(): ByteArray {
    val r = ByteArray(this.size shl 2)
    this.forEachIndexed { i, w ->
        r[i.shl(2)] = w.ushr(24).toByte()
        r[i.shl(2) + 1] = w.ushr(16).toByte()
        r[i.shl(2) + 2] = w.ushr(8).toByte()
        r[i.shl(2) + 3] = w.toByte()
    }
    return r
}

fun wordFromBytes(b0: Byte, b1: Byte, b2: Byte, b3: Byte): Word {
    return intFromBytes(b0, b1, b2, b3)
}

typealias MessageGroup = ByteArray // 每次迭代压缩的消息分组固定为16字，合64字节，计512比特。
fun WordArray.fill(messageGroup: MessageGroup) {
    // 字节数组长度必须为4的倍，由于仅在SM3内部使用，这里不做长度校验。
    for (i in 0 until 16) {
        this[i] = wordFromBytes(
                messageGroup[i.shl(2)],
                messageGroup[i.shl(2) + 1],
                messageGroup[i.shl(2) + 2],
                messageGroup[i.shl(2) + 3])
    }
}

fun Long.toWord(): Word {
    return this.toInt()
}

class SM3 {
    /**-
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
     *      +：mod2^32算术加运算
     *      ≪k：循环左移k比特运算
     *      ←：左向赋值运算符
     */
    /**
     * 单位：Byte
     */
    private val MSG_GROUP_LEN = 64 // B(i)消息分组容量。16字，合64字节，计512比特

    /**-
     *  4. 常数与函数
     *  4.1 初始值
     *  IV ＝ 7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e
     */
    private val IV: WordArray = wordArrayOf(0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600.toWord(), 0xa96f30bc.toWord(), 0x163138aa, 0xe38dee4d.toWord(), 0xb0fb0e4e.toWord())

    /**-
     *  4.2 常量
     *        79cc4519 0 ≤ j ≤ 15
     *  Tj ＝｛
     *        7a879d8a 16 ≤ j ≤ 63
     */
    private fun T(j: Int) = when (j) {
        in 0..15 -> 0x79cc4519
        in 16..63 -> 0x7a879d8a
        else -> throw IllegalArgumentException("j must in 0..63")
    }

    /**-
     *  4.3 布尔函数
     *                X ⊕ Y ⊕ Z                         0 ≤ j ≤ 15
     *  FFj(X,Y,Z) = {
     *                (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)       16 ≤ j ≤ 63
     *
     *                X ⊕ Y ⊕ Z                         0 ≤ j ≤ 15
     *  GGj(X,Y,Z) = {
     *                (X ∧ Y) ∨ (¬X ∧ Z)               16 ≤ j ≤ 63
     */
    private fun FF(j: Int): (X: Word, Y: Word, Z: Word) -> Word {
        return { X, Y, Z ->
            when (j) {
                in 0..15 -> X xor Y xor Z
                in 16..63 -> (X and Y) or (X and Z) or (Y and Z)
                else -> throw IllegalArgumentException("j must in 0..63")
            }
        }
    }

    private fun GG(j: Int): (X: Word, Y: Word, Z: Word) -> Word {
        return { X, Y, Z ->
            when (j) {
                in 0..15 -> X xor Y xor Z
                in 16..63 -> (X and Y) or (X.inv() and Z)
                else -> throw IllegalArgumentException("j must in 0..63")
            }
        }
    }

    /**-
     *  4.4 置换函数
     *  P0(X) = X ⊕ (X ≪ 9) ⊕ (X ≪ 17)
     *  P1(X) = X ⊕ (X ≪ 15) ⊕ (X ≪ 23)
     *  式中X为字。
     */
    private fun P0(X: Word) = X xor (X rshl 9) xor (X rshl 17)

    private fun P1(X: Word) = X xor (X rshl 15) xor (X rshl 23)

    /**-
     * 5. 算法描述
     * 5.1 概述
     * 对长度为l(l < 2⁶⁴) 比特的消息m,SM3杂凑算法经过填充和迭代压缩,生成杂凑值,杂凑值长度 为256比特。
     */

    /**-
     * 5.2 填充
     * 假设消息m的长度为l比特。首先将比特“1”添加到消息的末尾,再添加k个“0”,k是满足l+1+k≡448mod512的最小的非负整数。然后再添加一个64位比特串,该比特串是长度l的二进制表示。填充后的消息m′的比特长度为512的倍数。
     * 例如:
     * 对消息01100001 01100010 01100011,其长度l=24,经填充得到比特串:
     *            |24比特                    |1比特|423比特  |64比特
     *            01100001 01100010 01100011 1    00 ··· 00 00 ··· 011000
     *                                                     l的二进制表示
     */
    /**
     * 优化后的消息填充算法。在迭代压缩最后的阶段进行填充。
     * 改进后：
     * 1. 节约空间占用
     * 2. 支持流式数据运算
     */
    private fun updatePadding() { // 这里计算时已将bit转换为字节
        if (msgLen == 0L) throw IllegalStateException("No message found. Maybe digest(message) will help you.")
        var paddingLen = MSG_GROUP_LEN - bufferOffset
        if (paddingLen < 8) paddingLen = MSG_GROUP_LEN shl 1 - bufferOffset
        val padding = ByteArray(paddingLen)
        padding[0] = 0x80.toByte()
        msgLen.shl(3).toByteArray().forEachIndexed { i, byte ->
            padding[paddingLen - 8 + i] = byte
        }
        update(padding)
    }

    /**-
     * 5.3 迭代压缩
     * 5.3.1 迭代过程
     * 将填充后的消息m′按512比特进行分组:m′=B(0)B(1)···B(n−1)其中n=(l+k+65)/512。
     * 对m′按下列方式迭代:
     * FOR i=0 TO n-1
     *     V(i+1)=CF(V(i),B(i))
     * ENDFOR
     * 其中CF是压缩函数,V(0)为256比特初始值IV,B(i)为填充后的消息分组,迭代压缩的结果为V(n)。
     */
    /* 使用V寄存器保存运算结果V(i＋1)；同时它也是上次运算的结果（或初始向量IV），即V(i) */
    private val V = IV.copyOf()
    /* 使用buffer缓存传入的message。直到满足分组条件，即缓冲区填满。进行一次迭代压缩运算。*/
    /* 分组消息数据缓冲区。缓冲区一旦填满即进行迭代压缩运算，直至调用digest函数结束运算并获取结果。 */
    private val buffer = MessageGroup(MSG_GROUP_LEN)
    /* 缓冲区指针偏移量。当bufferOffset位于缓冲区尾时，调用digestMessage处理缓冲区数据，并重置指针。 */
    private var bufferOffset = 0

    /**-
     * 5.3.2 消息扩展
     * 将消息分组B(i)按以下方法扩展生成132个字W0,W1,···,W67,W′0,W′1,···,W′63,用于压缩函数CF:
     *   a)将消息分组B(i)划分为16个字W0,W1,···,W15。
     *   b)FOR j=16 TO 67
     *        Wj←P1(Wj−16⊕Wj−9⊕(Wj−3≪15))⊕(Wj−13≪7)⊕Wj−6
     *     ENDFOR
     *   c)FOR j=0 TO 63
     *        W′j=Wj⊕Wj+4
     *     ENDFOR
     */
    private val W = WordArray(68)
    private val W_ = WordArray(64)
    private fun processing(msgGroup: MessageGroup) {
        W.fill(msgGroup)
        for (j in 16..67) {
            W[j] = P1(W[j - 16] xor W[j - 9] xor W[j - 3].rshl(15)) xor W[j - 13].rshl(7) xor W[j - 6]
        }
        for (j in 0..63) {
            W_[j] = W[j] xor W[j + 4]
        }
    }

    /**-
     * 5.3.3 压缩函数
     * 令A,B,C,D,E,F,G,H为字寄存器,SS1,SS2,TT1,TT2为中间变量,压缩函数V(i+1)=CF(V(i),B(i))，0 ≤ i ≤ n-1。
     * 计算过程描述如下:
     *   ABCDEFGH ← V(i)
     *   FOR j=0 TO 63
     *     SS1←((A≪12)+E+(Tj≪j))≪7
     *     SS2←SS1⊕(A≪12)
     *     TT1←FFj(A,B,C) + D + SS2 + W′j
     *     TT2←GGj(E,F,G) + H + SS1 + Wj
     *     D←C
     *     C←B≪9
     *     B←A
     *     A←TT1
     *     H←G
     *     G←F≪19
     *     F←E
     *     E←P0(TT2)
     *   ENDFOR
     *   V(i+1)←ABCDEFGH⊕V(i)其中,字的存储为大端(big-endian)格式。
     */
    private fun digestMessage(msgGroup: MessageGroup) {
        processing(msgGroup)
        showExtensionBi()
        /* ABCDEFGH寄存器。8字，合32字节，计256比特 */
        var A = V[0]
        var B = V[1]
        var C = V[2]
        var D = V[3]
        var E = V[4]
        var F = V[5]
        var G = V[6]
        var H = V[7]
        // Begin CF, 运算结果符合公式 result = CF(result, Bi)
        for (j in 0..63) {
            val SS1 = ((A rshl 12) + E + (T(j) rshl j)) rshl 7
            val SS2 = SS1 xor (A rshl 12)
            val TT1 = FF(j)(A, B, C) + D + SS2 + W_[j]
            val TT2 = GG(j)(E, F, G) + H + SS1 + W[j]
            D = C
            C = B rshl 9
            B = A
            A = TT1
            H = G
            G = F rshl 19
            F = E
            E = P0(TT2)
            traceCF(j, A, B, C, D, E, F, G, H)
        }
        // V(i+1) = ABCDEFG ⊕ V(i)
        V[0] = A xor V[0]
        V[1] = B xor V[1]
        V[2] = C xor V[2]
        V[3] = D xor V[3]
        V[4] = E xor V[4]
        V[5] = F xor V[5]
        V[6] = G xor V[6]
        V[7] = H xor V[7]
        // End CF
    }

    /**-
     * 5.4 杂凑值
     * ABCDEFGH ← V(n)
     * 输出256比特的杂凑值y = ABCDEFGH。
     */
    private fun getMessageDigest(): ByteArray {
        if (!finish) throw IllegalStateException("Use digest(...) to get message digest.")
        val messageDigest = V.toByteArray()
        reset()
        return messageDigest
    }

    /* 记录已🉑️消息长度，Long型，8Bytes，64bit */
    private var msgLen = 0L
    /* 结束运算标记，用于判断是否可以调用getMessageDigest函数 */
    private var finish = false

    private fun reset() {
        resetBuffer()
        resetResult()
        resetMessageCounter()
        finish = false
    }

    private fun resetBuffer() {
        bufferOffset = 0
    }

    private fun resetResult() {
        IV.forEachIndexed { i, w ->
            V[i] = w
        }
    }

    private fun resetMessageCounter() {
        msgLen = 0
    }

    /**
     * @param message 消息
     */
    fun update(message: ByteArray, offset: Int, length: Int): SM3 {
        for (i in offset.until(length)) {
            buffer[bufferOffset++] = message[i]
            if (bufferOffset == MSG_GROUP_LEN) {
                digestMessage(buffer)
                resetBuffer()
            }
            traceMessage(message[i])
        }
        msgLen += length
        return this
    }

    /**
     * @param message 消息
     */
    fun update(message: ByteArray): SM3 {
        return update(message, 0, message.size)
    }

    /**
     * 计算消息摘要（增量方式）
     * 例：
     *    val sm3 = SM3()
     *    for(msg in msgList) {
     *      sm3.update(msg)
     *    }
     *    val sm3MessageDigest = sm3.digest()
     */
    fun digest(): ByteArray {
        showMessage("origin")
        updatePadding()
        showMessage("padded")
        finish = true
        return getMessageDigest()
    }

    /**
     * 计算消息摘要（全量方式）
     * 例：
     *    val sm3 = SM3()
     *    val sm3MessageDigest = sm3.digest(msg)
     *
     * @param message 消息
     */
    fun digest(message: ByteArray): ByteArray {
        return update(message).digest()
    }

    companion object {
        /**
         * 一次性计算，不推荐。
         * 例：
         *    val sm3MessageDigest = SM3.digest(msg)
         *
         * @param message 消息
         */
        fun digest(message: ByteArray): ByteArray {
            return SM3().digest(message)
        }

        // for debug
        val wordHexStyle = WordHexStyle()
    }

    /**
     * 用于调试的代码。在找到其他更好的方法代替前，暂时保留。
     */
    /*  BEGIN DEBUG CODE  */
    private var msg: MutableList<Byte>? = null

    private fun traceMessage(message: Byte) {
        if (SMxProperties.debug) {
            if (msg == null) {
                msg = ArrayList<Byte>()
            }
            msg?.add(message)
        }
    }

    private fun showMessage(prefix: String) {
        if (SMxProperties.debug) {
            debug("$prefix message:\r\n${msg?.toByteArray()?.toHexString(wordHexStyle)}")
        }
    }

    private fun showExtensionBi() {
        if (SMxProperties.debug) {
            debug("W0,W1,···,W67\r\n${W.toByteArray().toHexString(wordHexStyle)}")
            debug("W′0,W′1,···,W′63\r\n${W_.toByteArray().toHexString(wordHexStyle)}")
        }
    }

    private fun traceCF(i: Int, A: Int, B: Int, C: Int, D: Int, E: Int, F: Int, G: Int, H: Int) {
        if (SMxProperties.debug) {
            if (i == 0) debug(message = "   A        B        C        D        E        F        G        H    ")
            debug("$i\r\n"
                    + A.toByteArray().toHexString() + ' '
                    + B.toByteArray().toHexString() + ' '
                    + C.toByteArray().toHexString() + ' '
                    + D.toByteArray().toHexString() + ' '
                    + E.toByteArray().toHexString() + ' '
                    + F.toByteArray().toHexString() + ' '
                    + G.toByteArray().toHexString() + ' '
                    + H.toByteArray().toHexString()
            )
        }
    }

    private fun debug(message: String) {
        if (SMxProperties.debug) {
            println(message)
        }
    }


    class WordHexStyle : HexStringStyle {
        private var wc = 0 // 组计数器
        private var lc = 0 // 行计数器
        override fun appendTo(builder: StringBuilder, byteHexString: String, byteIndex: Int) {
            builder.append(byteHexString)
            if (wc++ == 3) { // 4bytes一组
                builder.append(' ')
                if (lc++ == 7) { // 8words一行
                    builder.append("\r\n")
                    lc = 0
                }
                wc = 0
            }
        }

        override fun reset() {
            wc = 0
            lc = 0
        }
    }
    /*  END DEBUG CODE  */
}