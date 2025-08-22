package fi.csc.shibboleth.authn.conf;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import org.testng.Assert;

/**
 * Unit tests for {@link DiscoveryFlows}.
 */
public class DiscoveryFlowsTest {

    private DiscoveryFlows discoveryFlows;

    @BeforeMethod
    protected void setUp() throws Exception {
        Map<String, Object> authenticatingAuthority = new HashMap<String, Object>();
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.ACR_KEY, "anyStringAcr");
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.AA_TYPE_KEY, "anyStringType");
        authenticatingAuthority.put(DiscoveryAuthenticatingAuthority.AA_VALUE_KEY, "anyStringValue");

        Map<String, List<Map<String, Object>>> flow = new HashMap<String, List<Map<String, Object>>>();
        flow.put("flow1", Arrays.asList(authenticatingAuthority));
        flow.put("flow2", Arrays.asList(authenticatingAuthority, authenticatingAuthority));
        discoveryFlows = DiscoveryFlows.parse(flow);
    }

    @Test
    public void testObjectParsingSuccess() throws Exception {
        Assert.assertTrue(discoveryFlows.getAuthorityMap().containsKey("flow1"));
    }

    @Test
    public void testSerialization() throws Exception {
        String serialized = discoveryFlows.toJSON();
        discoveryFlows = DiscoveryFlows.parse(serialized);
        Assert.assertTrue(discoveryFlows.getAuthorityMap().containsKey("flow1"));
        Assert.assertEquals(discoveryFlows.getAuthorityMap().get("flow2").size(), 2);
    }
}