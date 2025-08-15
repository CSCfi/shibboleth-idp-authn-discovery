/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.csc.shibboleth.authn.impl;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.csc.shibboleth.authn.AuthenticationDiscoveryContext;
import fi.csc.shibboleth.authn.conf.DiscoveryAuthenticatingAuthority;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.idp.profile.testing.RequestContextBuilder;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;

/**
 * Unit tests for {@link PopulateDiscoveryContext}.
 */
public class PopulateDiscoveryContextTest {

    /** The action to be tested. */
    private PopulateDiscoveryContext action;

    private AuthenticationContext authenticationContext;

    private RequestContext src;
    private ProfileRequestContext prc;

    private String configuration = "{\n" + "  \"default\": {\n" + "    \"authn/test1\": [\n" + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHakaTest\",\n"
            + "        \"aaType\": \"discovery\",\n"
            + "        \"aaValue\": \"https://testsp.funet.fi/shibboleth/WAYF\"\n" + "      },\n" + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHaka\",\n" + "        \"aaType\": \"entity\",\n"
            + "        \"aaValue\": \"https://idp.csc.fi/idp/shibboleth\"\n" + "      }\n" + "    ],\n"
            + "    \"authn/Password\": [\n" + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHakaCSC\",\n" + "        \"aaType\": \"entity\",\n"
            + "        \"aaValue\": \"https://testsp.funet.fi/shibboleth/WAYF\"\n" + "      }\n" + "    ]\n" + "  },\n"
            + "  \"IK1GX427KQ\": {\n" + "    \"authn/MFA\": [\n" + "      {\n"
            + "        \"acr\": \"https://dev-user-auth.csc.fi/LoginHakaTest\",\n"
            + "        \"aaType\": \"discovery\",\n"
            + "        \"aaValue\": \"https://testsp.funet.fi/shibboleth/WAYF\"\n" + "      }\n" + "    ]\n" + "  }\n"
            + "}";

    protected void initializeMembers() throws ComponentInitializationException {
        src = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(src);
        authenticationContext = (AuthenticationContext) prc.addSubcontext(new AuthenticationContext(), true);

        authenticationContext.getPotentialFlows().put("test1", new AuthenticationFlowDescriptor());
        authenticationContext.getPotentialFlows().get("test1").setId("authn/test1");
        authenticationContext.getPotentialFlows().put("test2", new AuthenticationFlowDescriptor());
        authenticationContext.getPotentialFlows().get("test2").setId("authn/test2");
        authenticationContext.getPotentialFlows().put("test3", new AuthenticationFlowDescriptor());
        authenticationContext.getPotentialFlows().get("test3").setId("authn/test3");

    }

    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        initializeMembers();
        action = new PopulateDiscoveryContext();
        action.setTrim(true);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        action.setHttpServletRequestSupplier(new NonnullSupplier<>() {
            public HttpServletRequest get() {
                return request;
            }
        });
    }

    @Test
    public void testBasicCase() throws Exception {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        AuthenticationDiscoveryContext discoContext = authenticationContext
                .getSubcontext(AuthenticationDiscoveryContext.class);
        Assert.assertNotNull(discoContext);
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().size(), 3);
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(0).getFirst(), "authn/test1");
        Assert.assertNull(discoContext.getFlowsWithAuthorities().get(0).getSecond());
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(1).getFirst(), "authn/test2");
        Assert.assertNull(discoContext.getFlowsWithAuthorities().get(1).getSecond());
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(2).getFirst(), "authn/test3");
        Assert.assertNull(discoContext.getFlowsWithAuthorities().get(2).getSecond());
    }

    @Test
    public void testDiscoveryProperties() throws Exception {
        action.setAuthorityProperties("./src/test/resources/discovery.properties");
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        AuthenticationDiscoveryContext discoContext = authenticationContext
                .getSubcontext(AuthenticationDiscoveryContext.class);
        Assert.assertNotNull(discoContext);
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().size(), 5);
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(0).getFirst(), "authn/test1");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(0).getSecond(), "authority1");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(1).getFirst(), "authn/test1");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(1).getSecond(), "authority2");

        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(2).getFirst(), "authn/test2");
        Assert.assertNull(discoContext.getFlowsWithAuthorities().get(2).getSecond());

        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(3).getFirst(), "authn/test3");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(3).getSecond(), "authority3");

        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(4).getFirst(), "authn/test3");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(4).getSecond(), "authority4");
    }

    @Test
    public void testJsonOverProperties() throws Exception {
        action.setAuthorityProperties("./src/test/resources/discovery.properties");
        action.setAuthorities(configuration);
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        AuthenticationDiscoveryContext discoContext = authenticationContext
                .getSubcontext(AuthenticationDiscoveryContext.class);
        Assert.assertNotNull(discoContext);
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().size(), 4);
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(0).getFirst(), "authn/test1");
        DiscoveryAuthenticatingAuthority discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority
                .parseB64UrlEncoded(discoContext.getFlowsWithAuthorities().get(0).getSecond());
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "https://dev-user-auth.csc.fi/LoginHakaTest");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getType(), "discovery");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getValue(), "https://testsp.funet.fi/shibboleth/WAYF");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(1).getFirst(), "authn/test1");
        discoveryAuthenticatingAuthority = DiscoveryAuthenticatingAuthority
                .parseB64UrlEncoded(discoContext.getFlowsWithAuthorities().get(1).getSecond());
        Assert.assertEquals(discoveryAuthenticatingAuthority.getAcr(), "https://dev-user-auth.csc.fi/LoginHaka");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getType(), "entity");
        Assert.assertEquals(discoveryAuthenticatingAuthority.getValue(), "https://idp.csc.fi/idp/shibboleth");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(1).getFirst(), "authn/test1");
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(2).getFirst(), "authn/test2");
        Assert.assertNull(discoContext.getFlowsWithAuthorities().get(2).getSecond());
        Assert.assertEquals(discoContext.getFlowsWithAuthorities().get(3).getFirst(), "authn/test3");
        Assert.assertNull(discoContext.getFlowsWithAuthorities().get(3).getSecond());
    }

}
