package fi.csc.shibboleth.authn.conf;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;


/**
 * Unit tests for {@link DiscoveryConfiguration}.
 */
public class DiscoveryConfigurationTest {

    private DiscoveryConfiguration discoveryConfiguration;
    
    private String configuration = "{\n"
            + "  \"default\": {\n"
            + "    \"authn/MFA\": [\n"
            + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHakaTest\",\n"
            + "        \"aaType\": \"discovery\",\n"
            + "        \"aaValue\": \"https://testsp.funet.fi/shibboleth/WAYF\"\n"
            + "      },\n"
            + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHaka\",\n"
            + "        \"aaType\": \"entity\",\n"
            + "        \"aaValue\": \"https://idp.csc.fi/idp/shibboleth\"\n"
            + "      }\n"
            + "    ],\n"
            + "    \"authn/Password\": [\n"
            + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHakaCSC\",\n"
            + "        \"aaType\": \"entity\",\n"
            + "        \"aaValue\": \"https://testsp.funet.fi/shibboleth/WAYF\"\n"
            + "      }\n"
            + "    ]\n"
            + "  },\n"
            + "  \"IK1GX427KQ\": {\n"
            + "    \"authn/MFA\": [\n"
            + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHakaTest\",\n"
            + "        \"aaType\": \"discovery\",\n"
            + "        \"aaValue\": \"https://testsp.funet.fi/shibboleth/WAYF\"\n"
            + "      }\n"
            + "    ]\n"
            + "  }\n"
            + "}";

    @BeforeMethod
    protected void setUp() throws Exception {
        discoveryConfiguration = DiscoveryConfiguration.parse(configuration);

    }

    @Test
    public void testRelyingPartyConfigurationExists() {
        // For IK1GX427KQ
        Assert.assertTrue(discoveryConfiguration.getFlowMap().containsKey("IK1GX427KQ"));
        // default
        Assert.assertTrue(discoveryConfiguration.getFlowMap().containsKey("default"));
    }

    @Test
    public void testNumberOfFlows() {
        // For IK1GX427KQ
        Assert.assertEquals(
                discoveryConfiguration.getFlowMap().get("IK1GX427KQ").getAuthorityMap().size(),
                1);
        // default
        Assert.assertEquals(
                discoveryConfiguration.getFlowMap().get("default").getAuthorityMap().size(), 2);
    }

    @Test
    public void findFlowPerACR() {
        Assert.assertEquals(findMatch("NotListed", "https://dev-user-auth.csc.fi/LoginHaka"), "authn/MFA");
        Assert.assertEquals(findMatch("IK1GX427KQ", "https://dev-user-auth.csc.fi/LoginHakaTest"), "authn/MFA");
        Assert.assertNull(findMatch("IK1GX427KQ", "https://dev-user-auth.csc.fi/LoginHakaCSC"));
        Assert.assertEquals(findMatch("NotListed", "https://dev-user-auth.csc.fi/LoginHakaCSC"), "authn/Password");
    }

    private String findMatch(String rp, String acr) {
        DiscoveryFlows rpConf = discoveryConfiguration.getFlowMap().containsKey(rp)
                ? discoveryConfiguration.getFlowMap().get(rp)
                : discoveryConfiguration.getFlowMap().get("default");
        String flowMatch = null;
        for (String flow : rpConf.getAuthorityMap().keySet()) {
            for (DiscoveryAuthenticatingAuthority authority : rpConf.getAuthorityMap().get(flow)) {
                if (acr.equals(authority.getAcr())) {
                    flowMatch = flow;
                    break;
                }
            }
            if (flowMatch != null) {
                break;
            }
        }
        return flowMatch;
    }

    @Test
    public void testSerialization() throws Exception {

        Assert.assertEquals(discoveryConfiguration.getFlowMap().get("default").getAuthorityMap()
                .get("authn/MFA").listIterator().next().getAcr(), "https://dev-user-auth.csc.fi/LoginHakaTest");
    }

}