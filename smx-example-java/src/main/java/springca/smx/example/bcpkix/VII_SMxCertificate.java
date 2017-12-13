package springca.smx.example.bcpkix;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static springca.smx.example.Warning.warning;
import static springca.smx.example.bcprov.III_SM2KeyPairGenerator.generateKeyPair;
import static springca.smx.example.bcprov.I_RegisterProvider.registerProvider;

@SuppressWarnings("WeakerAccess")
public class VII_SMxCertificate {
    public static void main(String[] args) {
        registerProvider();

        KeyPair kp = generateKeyPair();

        String subjectDN = "CN=Example SM2 Certificate";

        Certificate cert = buildSelfSignCertificate(subjectDN, kp);

        System.out.println("Certificate:\n" + cert);
        System.out.println("PEM        :\n" + toPem(cert));
    }

    @SuppressWarnings("UnnecessaryLocalVariable")
    private static Certificate buildSelfSignCertificate(String subjectDN, KeyPair kp) {
        X500Name subject = new X500Name(subjectDN);
        X500Name issuer = subject;
        BigInteger serialnumber = new BigInteger(new byte[]{0x61, 0x62, 0x63});
        Date notBefore = new Date(System.currentTimeMillis() - 60000);
        Date notAfter = new Date(System.currentTimeMillis() + 86400000);

        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serialnumber, notBefore, notAfter, subject, kp.getPublic());
            ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2").setProvider(PROVIDER_NAME).build(kp.getPrivate());
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                .setProvider(PROVIDER_NAME);
            return converter.getCertificate(builder.build(signer));
        } catch (OperatorCreationException e) {
            throw warning(e);
        } catch (CertificateException e) {
            throw warning(e);
        }
    }

    public static String toPem(Certificate cert) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(out));
            pemWriter.writeObject(cert);
            pemWriter.flush();
            byte[] pemEncoded = out.toByteArray();
            return new String(pemEncoded);
        } catch (IOException e) {
            throw warning(e);
        }
    }
}
