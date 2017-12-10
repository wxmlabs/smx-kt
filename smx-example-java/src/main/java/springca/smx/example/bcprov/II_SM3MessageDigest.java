package springca.smx.example.bcprov;

import org.bouncycastle.util.encoders.Hex;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static springca.smx.example.bcprov.I_RegisterProvider.registerProvider;
import static springca.smx.example.Warning.warning;

@SuppressWarnings("WeakerAccess")
public class II_SM3MessageDigest {
    public static void main(String[] args) {
        registerProvider();
        byte[] message = new byte[]{0x61, 0x62, 0x63};

        byte[] digest = digest(message);

        System.out.println("Message      :" + Hex.toHexString(message));
        System.out.println("MessageDigest:" + Hex.toHexString(digest));
    }

    public static byte[] digest(byte[] message) {
        try {
            MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER_NAME);
            return md.digest(message);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

}
