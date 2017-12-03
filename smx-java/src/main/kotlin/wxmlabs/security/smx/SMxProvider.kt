package wxmlabs.security.smx

import java.security.Provider
import java.security.Security

class SMxProvider() : Provider(name, version, info) {
    init {
        registerSM3MessageDigest()
    }

    private fun registerSM3MessageDigest() {
        put("MessageDigest.SM3",
                wxmlabs.security.smx.SM3MessageDigest::class.qualifiedName)
        put("Alg.Alias.MessageDigest.${SMxOID.SM3}", "SM3")
    }

    companion object {
        private val name = "SMx"
        private val version = 0.1
        private val info = "The cryptography provider for business of China."

        val INSTANCE = SMxProvider()
        fun register(position: Int = 0) {
            if (Security.getProvider(name) == null) {
                Security.insertProviderAt(INSTANCE, position)
            }
        }
    }
}