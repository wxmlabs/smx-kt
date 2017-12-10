package springca.smx.example;

import org.bouncycastle.operator.OperatorException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

@SuppressWarnings("WeakerAccess")
public class Warning extends RuntimeException {
    Warning(String message, Throwable cause) {
        super(message, cause);
    }

    public static Warning warning(GeneralSecurityException e) {
        String msg = e.getMessage();
        if (e instanceof NoSuchAlgorithmException) {
            msg = "请检查使用的BouncyCastle版本。需要 org.bouncycastle:bcprov-jdk15on:1.58 或更高";
        } else if (e instanceof NoSuchProviderException) {
            msg = "请检查是否已注册BouncyCastle。请参考 I_RegisterProvider";
        } else if (e instanceof InvalidAlgorithmParameterException) {
            for (StackTraceElement ste : e.getStackTrace()) {
                if (isGenerateKeyPair(ste)) {
                    msg = "参数错误。中国国产算法椭圆曲线参数在BC中命名为 sm2p256v1。";
                    break;
                }
            }
        }
        return new Warning(msg, e);
    }

    public static Warning warning(OperatorException e) {
        String msg = e.getMessage();
        return new Warning(msg, e);
    }

    public static Warning warning(IOException e) {
        String msg = e.getMessage();
        return new Warning(msg, e);
    }

    private static boolean isGenerateKeyPair(StackTraceElement ste) {
        return ste.getClassName().contains("KeyPairGenerator") && ste.getMethodName().equals("generateKeyPair");
    }

}
