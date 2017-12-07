package springca.smx.example;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class II_SM3MessageDigest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        I_RegisterProvider.registerProvider();
        MessageDigest md = MessageDigest.getInstance("SM3");
        byte[] digest = md.digest(new byte[]{0x61, 0x62, 0x63});
        System.out.println(new String(Hex.encode(digest)));
    }
}
