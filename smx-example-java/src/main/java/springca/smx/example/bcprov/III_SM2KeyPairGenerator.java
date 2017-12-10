package springca.smx.example.bcprov;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static springca.smx.example.bcprov.I_RegisterProvider.registerProvider;
import static springca.smx.example.Warning.warning;

@SuppressWarnings("WeakerAccess")
public class III_SM2KeyPairGenerator {
    public static void main(String[] args) {
        registerProvider();

        KeyPair kp = generateKeyPair();

        System.out.println("PrivateKey       :" + kp.getPrivate());
        System.out.println("PublicKey        :" + kp.getPublic());
        System.out.println("PrivateKey-Base64:" + Base64.toBase64String(kp.getPrivate().getEncoded()));
        System.out.println("PublicKey-Base64 :" + Base64.toBase64String(kp.getPublic().getEncoded()));
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", PROVIDER_NAME);
            kpGen.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
            return kpGen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

}
