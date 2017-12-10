package springca.smx.example.bcprov;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

@SuppressWarnings("WeakerAccess")
public class I_RegisterProvider {
    private static final Provider provider = new BouncyCastleProvider();

    public static void main(String[] args) {
        check();

        registerProvider();
        check();
        unregisterProvider();
        check();

        int position = 1;
        registerProviderWithPosition(position);
        check();
        unregisterProvider();
        check();
    }

    /**
     * 使用Security注册Provider
     */
    public static void registerProvider() {
        if (isNotRegistered()) {
            Security.addProvider(provider);
        }
    }

    /**
     * 使用指定优先级注册Provider。优先级取值为自然熟。position值越低，优先级越高。
     */
    public static void registerProviderWithPosition(int position) {
        if (isNotRegistered()) {
            Security.insertProviderAt(provider, position);
        }
    }

    public static void unregisterProvider() {
        if (isRegistered()) {
            Security.removeProvider(PROVIDER_NAME);
        }
    }

    public static void check() {
        if (isRegistered()) {
            System.out.println("Provider已注册。 <- Security.insertProviderAt(provider, position)");
        } else {
            System.out.println("Provider未注册。 <- Security.removeProvider(PROVIDER_NAME)");
        }
    }

    public static boolean isRegistered(){
        return Security.getProvider(PROVIDER_NAME) != null;
    }

    public static boolean isNotRegistered(){
        return !isRegistered();
    }

}
