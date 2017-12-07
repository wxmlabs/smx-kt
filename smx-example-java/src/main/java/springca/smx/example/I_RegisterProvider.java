package springca.smx.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

public class I_RegisterProvider {
    private static final Provider provider = new BouncyCastleProvider();

    /**
     * 使用Security注册Provider
     */
    public static void registerProvider() {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(provider);
        }
        assert Security.getProvider(PROVIDER_NAME) != null;
        System.out.println("Provider已注册。 <- Security.addProvider(provider)");
    }

    /**
     * 使用指定优先级注册Provider。优先级取值为自然熟。position值越低，优先级越高。
     */
    public static void registerProviderWithPosition(int position) {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.insertProviderAt(provider, position);
        }
        assert Security.getProvider(PROVIDER_NAME) != null;
        System.out.println("Provider已注册。 <- Security.insertProviderAt(provider, position)");
    }

    public static void unregisterProvider() {
        Security.removeProvider(PROVIDER_NAME);
        assert Security.getProvider(PROVIDER_NAME) == null;
        System.out.println("Provider已注销。 <- Security.removeProvider(PROVIDER_NAME)");
    }

    public static void main(String[] args) {
        registerProvider();
        unregisterProvider();

        int position = 1;
        registerProviderWithPosition(position);
        unregisterProvider();
    }
}
