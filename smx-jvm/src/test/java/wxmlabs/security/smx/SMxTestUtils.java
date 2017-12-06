package wxmlabs.security.smx;

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;

public class SMxTestUtils {
    // expect registered services and algorithms
    static HashMap<String, String> expect = new HashMap<String, String>(1);

    static {
        expect.put("MessageDigest.SM3", "");
    }

    /**
     * 清理实现了SMx算法的其它Providers
     */
    public static void cleanOtherProviders() {
        Provider[] providers = Security.getProviders(expect);
        if (providers != null && providers.length > 0) {
            for (Provider p : providers) {
                System.out.println(p);
                Security.removeProvider(p.getName());
            }
        }
        assert !Security.getAlgorithms("MessageDigest").contains("SM3");
    }

    public static byte[] intArray2Bytes(int[] input) {
        return wxmlabs.security.smx.SM3Kt.toByteArray(input);
    }
}
