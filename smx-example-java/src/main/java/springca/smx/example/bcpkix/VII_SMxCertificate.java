package springca.smx.example.bcpkix;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
import static springca.smx.example.Warning.warning;
import static springca.smx.example.bcprov.III_SM2KeyPairGenerator.generateKeyPair;
import static springca.smx.example.bcprov.I_RegisterProvider.registerProvider;

@SuppressWarnings("WeakerAccess")
public class VII_SMxCertificate {
    public static void main(String[] args) {
        registerProvider();

        KeyPair rootKeyPair = generateKeyPair();
        KeyPair subjectKeyPair = generateKeyPair();

        String rootDN = "CN=Example SM2 Root Certificate";
        String subjectDN = "CN=Example SM2 Certificate";

        try {
            X509Certificate rootCert = buildSelfSignCertificate(rootDN, rootKeyPair);
            byte[] rootEncoded = rootCert.getEncoded();
            String rootPEM = toPem(rootCert);

            X509Certificate cert = issueCertificate(subjectDN, subjectKeyPair.getPublic(), rootCert, rootKeyPair.getPrivate(), false);
            byte[] certEncoded = cert.getEncoded();
            String certPEM = toPem(cert);

            X509CRL crl = revokeCertificate(cert, CRLReason.lookup(CRLReason.privilegeWithdrawn), rootCert, rootKeyPair.getPrivate());
            byte[] crlEncoded = crl.getEncoded();
            String crlPEM = toPem(crl);
            boolean isRevoked = crl.isRevoked(cert);

            System.out.println("Root Certificate:\n" + rootCert);
            System.out.println("Encoded         :\n" + Hex.toHexString(rootEncoded));
            System.out.println("PEM             :\n" + certPEM);
            System.out.println("Binary retrieve :" + retrieveCertificate(rootEncoded).equals(rootCert));
            System.out.println("PEM retrieve    :" + fromPem(rootPEM).equals(rootCert));
            System.out.println(Strings.lineSeparator());
            System.out.println("Certificate     :\n" + cert);
            System.out.println("Encoded         :\n" + Hex.toHexString(certEncoded));
            System.out.println("PEM             :\n" + certPEM);
            System.out.println("Binary retrieve :" + retrieveCertificate(certEncoded).equals(cert));
            System.out.println("PEM retrieve    :" + fromPem(certPEM).equals(cert));
            System.out.println(Strings.lineSeparator());
            System.out.println("CRL             :\n" + crl);
            System.out.println("Encoded         :\n" + Hex.toHexString(crlEncoded));
            System.out.println("PEM             :\n" + crlPEM);
            System.out.println("Binary retrieve :" + retrieveCRL(crlEncoded).equals(crl));
            System.out.println("PEM retrieve    :" + fromPem(crlPEM).equals(crl));
            System.out.println("Is revoked      :" + isRevoked);

        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (CRLException e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("UnnecessaryLocalVariable")
    public static X509Certificate buildSelfSignCertificate(String subjectDN, KeyPair kp) {
        return issueCertificate(subjectDN, kp.getPublic(), null, kp.getPrivate(), true);
    }

    public static Certificate retrieveCertificate(byte[] derEncoded) {
        try {
            ByteArrayInputStream bIn = new ByteArrayInputStream(derEncoded);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
            return cf.generateCertificate(bIn);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }

    public static CRL retrieveCRL(byte[] derEncoded) {
        try {
            ByteArrayInputStream bIn = new ByteArrayInputStream(derEncoded);
            CertificateFactory cf = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
            return cf.generateCRL(bIn);
        } catch (GeneralSecurityException e) {
            throw warning(e);
        }
    }


    public static String toPem(Object obj) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(out));
            pemWriter.writeObject(obj);
            pemWriter.flush();
            byte[] pemEncoded = out.toByteArray();
            return new String(pemEncoded);
        } catch (IOException e) {
            throw warning(e);
        }
    }

    public static Object fromPem(String pemEncoded) {
        try {
            PEMParser parser = new PEMParser(new StringReader(pemEncoded));
            return convertToJcaObject(parser.readObject());
        } catch (IOException e) {
            throw warning(e);
        }
    }

    public static Object convertToJcaObject(Object obj) {
        if (obj instanceof X509CertificateHolder) {
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(PROVIDER_NAME);
            try {
                return converter.getCertificate((X509CertificateHolder) obj);
            } catch (CertificateException e) {
                throw warning(e);
            }
        } else if (obj instanceof X509CRLHolder) {
            JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider(PROVIDER_NAME);
            try {
                return converter.getCRL((X509CRLHolder) obj);
            } catch (CRLException e) {
                throw warning(e);
            }
        }
        return null;
    }

    public static X509Certificate issueCertificate(String subjectDN, PublicKey subjectPublicKey, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey, boolean isCACert) {
        X500Name subjectX500Name = new X500Name(subjectDN);
        X500Name issuerX500Name;
        PublicKey issuerPublicKey;
        if (issuerCertificate != null) {
            issuerX500Name = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
            issuerPublicKey = issuerCertificate.getPublicKey();
        } else {
            issuerX500Name = subjectX500Name;
            issuerPublicKey = subjectPublicKey;
        }
        BigInteger serialnumber = generateRandomSerialnumber();
        Date notBefore = new Date(System.currentTimeMillis() - 60000);
        Date notAfter = new Date(System.currentTimeMillis() + 86400000);

        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerX500Name, serialnumber, notBefore, notAfter, subjectX500Name, subjectPublicKey);
            builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extUtils.createSubjectKeyIdentifier(subjectPublicKey));

            builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extUtils.createAuthorityKeyIdentifier(issuerPublicKey));

            builder.addExtension(
                Extension.basicConstraints,
                false,
                new BasicConstraints(isCACert));
            ContentSigner signer = new JcaContentSignerBuilder("SM3withSM2").setProvider(PROVIDER_NAME).build(issuerPrivateKey);
            return (X509Certificate) convertToJcaObject(builder.build(signer));
        } catch (OperatorCreationException e) {
            throw warning(e);
        } catch (CertIOException e) {
            throw warning(e);
        } catch (NoSuchAlgorithmException e) {
            throw warning(e);
        }
    }

    private static final SecureRandom sr = new SecureRandom();

    public static BigInteger generateRandomSerialnumber() {
        byte[] randomSerialnumber = new byte[16];
        sr.nextBytes(randomSerialnumber);
        return new BigInteger(randomSerialnumber);
    }

    public static X509CRL revokeCertificate(X509Certificate certificate, CRLReason reason, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
        Date now = new Date();
        X500Name issuerX500Name = X500Name.getInstance(issuerCertificate.getSubjectX500Principal().getEncoded());
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuerX500Name, now);
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.issuingDistributionPoint, true, new IssuingDistributionPoint(null, true, false));
            builder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCertificate.getPublicKey()));

            ExtensionsGenerator extGen = new ExtensionsGenerator();

            extGen.addExtension(Extension.reasonCode, false, reason);
            extGen.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(issuerX500Name)));

            builder.setNextUpdate(new Date(now.getTime() + 100000));
            builder.addCRLEntry(certificate.getSerialNumber(), new Date(), extGen.generate());

            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SM3withSM2");
            contentSignerBuilder.setProvider(PROVIDER_NAME);

            X509CRLHolder cRLHolder = builder.build(contentSignerBuilder.build(issuerPrivateKey));
            return (X509CRL) convertToJcaObject(cRLHolder);
        } catch (OperatorCreationException e) {
            throw warning(e);
        } catch (CertIOException e) {
            throw warning(e);
        } catch (IOException e) {
            throw warning(e);
        } catch (NoSuchAlgorithmException e) {
            throw warning(e);
        }
    }
}
