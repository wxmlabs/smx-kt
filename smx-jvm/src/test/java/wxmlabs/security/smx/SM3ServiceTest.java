package wxmlabs.security.smx;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SM3ServiceTest {
    private static final byte[] input = new byte[]{0x61, 0x62, 0x63};
    private static final byte[] expect = SMxTestUtils.intArray2Bytes(new int[]{0x66c7f0f4, 0x62eeedd9, 0xd1f2d46b, 0xdc10e4e2, 0x4167c487, 0x5cf2f7a2, 0x297da02b, 0x8f4ba8e0});

    @BeforeClass
    public static void setUpBeforeClass() {
        SMxTestUtils.cleanOtherProviders();
        SMxProvider.register();
    }

    @AfterClass
    public static void tearDownAfterClass() {
        SMxProvider.unregister();
    }

    @Test
    public void testDigest() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SM3");
        byte[] digest = md.digest(input);
        Assert.assertArrayEquals("SM3 Message Digest Service", digest, expect);
    }

    @Test
    public void testUpdateAndDigest() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SM3");
        for (byte b : input) {
            md.update(b);
        }
        byte[] digest = md.digest();
        Assert.assertArrayEquals("SM3 Message Digest Service", digest, expect);
    }
}
