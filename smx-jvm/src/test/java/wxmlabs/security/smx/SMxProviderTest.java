package wxmlabs.security.smx;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.Security;

public class SMxProviderTest {


    @Before
    public void setUp() {
        // clean for test
        SMxTestUtils.cleanOtherProviders();
    }

    @After
    public void tearDown() {
        SMxProvider.unregister();
    }

    @Test
    public void testRegister() {
        SMxProvider.register();
        Assert.assertNotNull("SMx Provider registered.", Security.getProvider(SMxProvider.NAME));
        SMxProvider.unregister();
        Assert.assertNull("SMx Provider unregistered.", Security.getProvider(SMxProvider.NAME));
    }

    @Test
    public void testRegisterByJavaSecurity() {
        Security.addProvider(SMxProvider.INSTANCE);
        Assert.assertNotNull("SMx Provider registered.", Security.getProvider(SMxProvider.NAME));
        Security.removeProvider(SMxProvider.NAME);
        Assert.assertNull("SMx Provider unregistered.", Security.getProvider(SMxProvider.NAME));
    }

    @Test
    public void testNAME() {
        Assert.assertEquals("SMxProvider.NAME is the easy way for the SMx provider name", SMxProvider.NAME, new SMxProvider().getName());
    }

    @Test
    public void testINSTANCE() {
        Assert.assertEquals("SMxProvider.INSTANCE is a singleton of the SMx provider", SMxProvider.INSTANCE, new SMxProvider());
    }

    @Test
    public void testRegisteredServicesAndAlgorithms() {
        SMxProvider.register();
        for (String filterKey : SMxTestUtils.expect.keySet()) {
            int algIndex = filterKey.indexOf('.');
            int attrIndex = filterKey.indexOf(' ');
            assert algIndex > 0;
            String serviceName = filterKey.substring(0, algIndex);
            String algName;
            if (attrIndex == -1) {
                algName = filterKey.substring(algIndex + 1).trim();
            } else {
                algName = filterKey.substring(algIndex + 1, attrIndex);
            }
            Assert.assertTrue(Security.getAlgorithms(serviceName).contains(algName));
        }
    }

}
