package wxmlabs.security.smx

import java.security.AccessController
import java.security.PrivilegedAction
import java.security.Provider
import java.security.Security

/**
 * 代码中动态注册
 * <pre>
 * import java.security.Security;
 * import wxmlabs.security.smx.SMxProvider;
 *
 * Security.addProvider(new SMxProvider());
 * // or
 * // SMxProvider.register();
 * </pre>
 */
class SMxProvider : Provider(NAME, version, info) {
    init {
        registerSM3MessageDigest()
    }

    private fun registerSM3MessageDigest() {
        registerService("MessageDigest", "SM3", SM3MessageDigest::class.java.name, SMxOID.SM3)
    }

    /**
     * @param service   服务名 如：Signature, MessageDigest, Cipher等
     * @param algorithm 算法名 如：SM3withSM2, SM3, SM4等
     * @param instance  算法实现类 如："wxmlabs.security.smx.SM3MessageDigest"
     * @param aliases   算法别名 如：SM3算法的OID "1.2.156.10197.1.401"
     */
    private fun registerService(service: String, algorithm: String, instance: String, vararg aliases: String) {
        AccessController.doPrivileged(PrivilegedAction<Void> {
            val algorithmKey = String.format("%s.%s", service, algorithm)
            put(algorithmKey, instance)
            if (aliases.isNotEmpty()) {
                aliases
                    .map { alias -> "Alg.Alias.$service.$alias" /* aliasKey:String */ }
                    .forEach { aliasKey -> put(aliasKey, algorithm) }
            }
            null
        })
    }

    companion object {
        const val NAME = "SMx"
        private val version = 0.1
        private val info = "SMx Provider, the cryptography smx for business of China (implements SM3, SM4, SM2)."

        /**
         * SMxProvider实例
         */
        @JvmField
        val INSTANCE = SMxProvider()

        /**
         * 注册SMX
         */
        @JvmStatic
        fun register() {
            if (Security.getProvider(NAME) == null) {
                Security.addProvider(INSTANCE)
            }
        }

        /**
         * 注销SMX
         */
        @JvmStatic
        fun unregister() {
            if (Security.getProvider(NAME) != null) {
                Security.removeProvider(NAME)
            }
        }
    }
}
