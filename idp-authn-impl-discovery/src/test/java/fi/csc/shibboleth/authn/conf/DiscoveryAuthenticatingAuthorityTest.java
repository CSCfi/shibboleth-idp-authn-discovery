package fi.csc.shibboleth.authn.conf;

import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import org.testng.Assert;

/**
 * Unit tests for {@link DiscoveryAuthenticatingAuthority}.
 */
public class DiscoveryAuthenticatingAuthorityTest {

    private DiscoveryAuthenticatingAuthority discoveryAuthenticatingAuthority;

    @BeforeMethod
    protected void setUp() throws Exception {
        Map<String, Object> authenticatingAuthority = new HashMap<String, Object>();
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.ACR_KEY, "anyStringAcr");
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.AA_TYPE_KEY, "anyStringType");
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.AA_VALUE_KEY, "anyStringValue");
        discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parse(authenticatingAuthority);
    }

    @Test
    public void testObjectParsingSuccess() throws Exception {
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "anyStringAcr");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getType(), "anyStringType");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getValue(), "anyStringValue");
        Assert.assertFalse(discoveryAuthenticatingAuthority.isHidden());
    }

    @Test
    public void testSerialization() throws Exception {
        String serialized = discoveryAuthenticatingAuthority.toJSON();
        discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parse(serialized);
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "anyStringAcr");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getType(), "anyStringType");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getValue(), "anyStringValue");
    }

    @Test
    public void testParsingMinimal() throws Exception {
        String serialized = "{\"acr\":\"anyStringValue\"}";
        discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parse(serialized);
        Assert.assertNull(discoveryAuthenticatingAuthority.getType());
        Assert.assertNull(discoveryAuthenticatingAuthority.getValue());
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "anyStringValue");
    }
}