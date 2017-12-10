package springca.smx.example.bcprov;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static springca.smx.example.Warning.warning;

@SuppressWarnings("WeakerAccess")
public class V_SM4Cipher {
    public static void main(String[] args) {
        I_RegisterProvider.registerProvider();

        byte[] origin = new byte[]{0x61, 0x62, 0x63};
        SecretKey key = generateKey();

        byte[] encrypted = encrypt(origin, key);

        byte[] decrypted = decrypt(encrypted, key);

        System.out.println("Origin   :" + Hex.toHexString(origin));
        System.out.println("Encrypted:" + Hex.toHexString(encrypted));
        System.out.println("Decrypted:" + Hex.toHexString(decrypted));
    }

    public static SecretKey generateKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("SM4");
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static byte[] encrypt(byte[] origin, SecretKey key) {
        try {
            Cipher encryptor = Cipher.getInstance("SM4", PROVIDER_NAME);
            encryptor.init(Cipher.ENCRYPT_MODE, key);
            return encryptor.doFinal(origin);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static byte[] decrypt(byte[] encrypted, SecretKey key) {
        try {
            Cipher decryptor = Cipher.getInstance("SM4", PROVIDER_NAME);
            decryptor.init(Cipher.DECRYPT_MODE, key);
            return decryptor.doFinal(encrypted);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }
}
