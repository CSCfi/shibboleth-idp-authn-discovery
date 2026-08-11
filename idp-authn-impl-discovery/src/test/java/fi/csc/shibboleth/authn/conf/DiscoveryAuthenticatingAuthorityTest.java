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
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.FLOW_KEY, "anyStringFlow");
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.NAME_KEY, "anyStringName");
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.HIDDEN_KEY, true);
        discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parse(authenticatingAuthority);
    }

    @Test
    public void testObjectParsingSuccess() throws Exception {
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "anyStringAcr");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getType(), "anyStringType");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getValue(), "anyStringValue");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getName(), "anyStringName");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getFlow(), "anyStringFlow");
        Assert.assertTrue(discoveryAuthenticatingAuthority.isHidden());
    }

    @Test
    public void testSerialization() throws Exception {
        String serialized = discoveryAuthenticatingAuthority.toJSON();
        discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parse(serialized);
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "anyStringAcr");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getType(), "anyStringType");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getValue(), "anyStringValue");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getFlow(), "anyStringFlow");
        Assert.assertTrue(discoveryAuthenticatingAuthority.isHidden());
    }

    @Test
    public void testParsingMinimal() throws Exception {
        String serialized = "{\"acr\":\"https://test.com/acrname\"}";
        discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority.parse(serialized);
        Assert.assertNull(discoveryAuthenticatingAuthority.getType());
        Assert.assertNull(discoveryAuthenticatingAuthority.getValue());
        Assert.assertNull(discoveryAuthenticatingAuthority.getFlow());
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "https://test.com/acrname");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getName(), "acrname");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testMissingAcrThrows() {
        Map<String, Object> obj = new HashMap<String, Object>();
        obj.put(DiscoveryAuthenticatingAuthority.AA_TYPE_KEY, "entity");
        obj.put(DiscoveryAuthenticatingAuthority.AA_VALUE_KEY, "https://idp.example.com/idp");
        DiscoveryAuthenticatingAuthority.parse(obj);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testMalformedJsonThrows() {
        DiscoveryAuthenticatingAuthority.parse("{not json");
    }

    @Test
    public void testUtf8RoundTrip() throws Exception {
        Map<String, Object> obj = new HashMap<String, Object>();
        obj.put(DiscoveryAuthenticatingAuthority.ACR_KEY, "https://example.com/naïve");
        obj.put(DiscoveryAuthenticatingAuthority.NAME_KEY, "häkä-识");
        DiscoveryAuthenticatingAuthority original = DiscoveryAuthenticatingAuthority.parse(obj);
        String encoded = original.toB64UrlEncoded();
        DiscoveryAuthenticatingAuthority decoded = DiscoveryAuthenticatingAuthority.parseB64UrlEncoded(encoded);
        Assert.assertEquals(decoded.getAcr(), "https://example.com/naïve");
        Assert.assertEquals(decoded.getName(), "häkä-识");
    }
}