package springca.smx.example.bcprov;

import org.bouncycastle.util.encoders.Hex;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static springca.smx.example.bcprov.I_RegisterProvider.registerProvider;
import static springca.smx.example.Warning.warning;

@SuppressWarnings("WeakerAccess")
public class IV_SM3withSM2Signature {
    public static void main(String[] args) {
        registerProvider();

        KeyPair kp = III_SM2KeyPairGenerator.generateKeyPair();

        byte[] plaintext = new byte[]{0x61, 0x62, 0x63};
        byte[] signature = sign(plaintext, kp.getPrivate());
        boolean isVerified = verify(plaintext, signature, kp.getPublic());
        System.out.println("plaintext:" + Hex.toHexString(plaintext));
        System.out.println("signature:" + Hex.toHexString(signature));
        System.out.println("verified :" + isVerified);
    }

    public static byte[] sign(byte[] plaintext, PrivateKey privateKey) {
        try {
            Signature signer = Signature.getInstance("SM3withSM2", PROVIDER_NAME);
            signer.initSign(privateKey);
            signer.update(plaintext);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static boolean verify(byte[] plaintext, byte[] signature, PublicKey publicKey) {
        try {
            Signature signer = Signature.getInstance("SM3withSM2", PROVIDER_NAME);
            signer.initVerify(publicKey);
            signer.update(plaintext);
            return signer.verify(signature);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

}
