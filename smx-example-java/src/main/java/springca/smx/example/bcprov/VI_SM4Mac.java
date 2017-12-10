package springca.smx.example.bcprov;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.GeneralSecurityException;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static springca.smx.example.Warning.warning;
import static springca.smx.example.bcprov.I_RegisterProvider.registerProvider;

@SuppressWarnings("WeakerAccess")
public class VI_SM4Mac {
    public static void main(String[] args) {
        registerProvider();

        byte[] data = new byte[]{0x61, 0x62, 0x63};

        SecretKey cMacKey = generateCMacKey();
        byte[] cMac = cMac(data, cMacKey);

        SecretKey gMacKey = generateGMacKey();
        byte[] gMac = gMac(data, gMacKey);

        SecretKey poly1305Key = generatePoly1305Key();
        byte[] poly1305 = poly1305(data, poly1305Key);

        System.out.println("Data    :" + Hex.toHexString(data));
        System.out.println("CMac    :" + Hex.toHexString(cMac));
        System.out.println("GMac    :" + Hex.toHexString(gMac));
        System.out.println("Poly1305:" + Hex.toHexString(poly1305));
    }


    public static SecretKey generateCMacKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("SM4-CMac", PROVIDER_NAME);
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static byte[] cMac(byte[] data, SecretKey key) {
        try {
            Mac mac = Mac.getInstance("SM4-CMac");
            mac.init(key);
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static SecretKey generateGMacKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("SM4-GMac", PROVIDER_NAME);
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static byte[] gMac(byte[] data, SecretKey key) {
        try {
            Mac mac = Mac.getInstance("SM4-GMac");
            mac.init(key, generateIvParameterSpec());
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static SecretKey generatePoly1305Key() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("Poly1305-SM4", PROVIDER_NAME);
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static byte[] poly1305(byte[] data, SecretKey key) {
        try {
            Mac mac = Mac.getInstance("Poly1305-SM4", PROVIDER_NAME);
            mac.init(key, generateIvParameterSpec());
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static IvParameterSpec generateIvParameterSpec() {
        try {
            return AlgorithmParameterGenerator.getInstance("SM4", PROVIDER_NAME).generateParameters().getParameterSpec(IvParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }
}
