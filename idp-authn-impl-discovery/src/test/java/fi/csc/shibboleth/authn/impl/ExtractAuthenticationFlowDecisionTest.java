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

import java.util.List;

import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.csc.shibboleth.authn.AuthenticationDiscoveryContext;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.profile.testing.ActionTestingSupport;
import net.shibboleth.idp.profile.testing.RequestContextBuilder;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;

/**
 * Unit tests for {@link ExtractAuthenticationFlowDecision}.
 */
public class ExtractAuthenticationFlowDecisionTest {

    /** The action to be tested. */
    private ExtractAuthenticationFlowDecision action;

    /** The authentication flow field name coming from UI. */
    private String authnFlowField;

    /** The authentication flow decision. */
    private String authnFlowDecision;

    /** The authentication flow decision. */
    private String authnFlowDecision2;

    /** The authentication authority field name coming from UI. */
    private String authnAuthorityField;

    /** The authentication authority decision. */
    private String authnAuthorityDecision;

    private RequestContext src;
    private ProfileRequestContext prc;
    private List<AuthenticationFlowDescriptor> authenticationFlows;

    protected void initializeMembers() throws ComponentInitializationException {
        src = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(src);
        prc.addSubcontext(new AuthenticationContext(), true);

        authenticationFlows = List.of(new AuthenticationFlowDescriptor(), new AuthenticationFlowDescriptor(),
                new AuthenticationFlowDescriptor());
        authenticationFlows.get(0).setId("test1");
        authenticationFlows.get(1).setId("test2");
        authenticationFlows.get(1).setPassiveAuthenticationSupported(true);
        authenticationFlows.get(2).setId("test3");
    }

    /**
     * {@inheritDoc}
     * 
     * @throws ComponentInitializationException
     */
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        initializeMembers();
        authnFlowField = "mockAuthnFlowField";
        authnFlowDecision = "mockDecision";
        authnFlowDecision2 = "mockDecision2";
        authnAuthorityField = "mockAuthnAuthorityField";
        authnAuthorityDecision = "mockAuthorityDecision";
        AuthenticationDiscoveryContext discoveryCtx = (AuthenticationDiscoveryContext) prc
                .getSubcontext(AuthenticationContext.class).addSubcontext(new AuthenticationDiscoveryContext());
        discoveryCtx.getFlowsWithAuthorities().add(new Pair<String, String>("mockDecision", "mockAuthorityDecision"));
        discoveryCtx.getFlowsWithAuthorities().add(new Pair<String, String>("mockDecision2", null));
        action = new ExtractAuthenticationFlowDecision();
        action.setTrim(true);
        action.setAuthnFlowFieldName(authnFlowField);
        action.setSelectedAuthorityFieldName(authnAuthorityField);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        action.setHttpServletRequestSupplier(new NonnullSupplier<>() {
            public HttpServletRequest get() {
                return request;
            }
        });
    }

    /**
     * Runs the action without {@link HttpServletRequest}.
     */
    @Test
    public void testMissingServlet() throws Exception {
        action.setHttpServletRequestSupplier(null);
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.REQUEST_UNSUPPORTED);
    }

    /**
     * Runs the action with invalid input.
     */
    @Test
    public void testNoDecision() throws Exception {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.REQUEST_UNSUPPORTED);
    }

    /**
     * Runs the action with valid input without authority.
     */
    @Test
    public void testValidNoAuthority() throws Exception {
        action.initialize();
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnFlowField, authnFlowDecision2);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.RESELECT_FLOW);
        AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        Assert.assertNotNull(authCtx);
        Assert.assertEquals(authCtx.getSignaledFlowId(), authnFlowDecision2);
        Assert.assertNull(authCtx.getAuthenticatingAuthority());
    }

    /**
     * Runs the action with valid input without authority that should be there.
     */
    @Test
    public void testInValidNoAuthority() throws Exception {
        action.initialize();
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnFlowField, authnFlowDecision);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.REQUEST_UNSUPPORTED);
        AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        Assert.assertNotNull(authCtx);
        Assert.assertNull(authCtx.getSignaledFlowId());
        Assert.assertNull(authCtx.getAuthenticatingAuthority());
    }

    /**
     * Runs the action with valid input with authority.
     */
    @Test
    public void testValidWithAuthority() throws Exception {
        action.initialize();
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnFlowField, authnFlowDecision);
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnAuthorityField,
                authnAuthorityDecision);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.RESELECT_FLOW);
        AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        Assert.assertNotNull(authCtx);
        Assert.assertEquals(authCtx.getSignaledFlowId(), authnFlowDecision);
        Assert.assertEquals(authCtx.getAuthenticatingAuthority(), authnAuthorityDecision);
    }

    /**
     * Runs the action with valid input with input needing trim.
     */
    @Test
    public void testValidWithAuthorityTrim() throws Exception {
        action.initialize();
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnFlowField, " " + authnFlowDecision);
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnAuthorityField,
                authnAuthorityDecision + " ");
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.RESELECT_FLOW);
        AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        Assert.assertNotNull(authCtx);
        Assert.assertEquals(authCtx.getSignaledFlowId(), authnFlowDecision);
        Assert.assertEquals(authCtx.getAuthenticatingAuthority(), authnAuthorityDecision);
    }

    /**
     * Runs the action with invalid authority.
     */
    @Test
    public void testInvalidAuthority() throws Exception {
        action.initialize();
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnFlowField, authnFlowDecision);
        ((MockHttpServletRequest) action.getHttpServletRequest()).addParameter(authnAuthorityField,
                authnAuthorityDecision + "_invalid");
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.REQUEST_UNSUPPORTED);
        AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class);
        Assert.assertNotNull(authCtx);
        Assert.assertNull(authCtx.getSignaledFlowId());
        Assert.assertNull(authCtx.getAuthenticatingAuthority());
    }
}
