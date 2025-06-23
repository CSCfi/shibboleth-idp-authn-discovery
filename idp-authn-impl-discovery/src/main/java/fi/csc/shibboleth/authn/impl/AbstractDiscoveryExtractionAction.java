/*
 * The MIT License
 * Copyright (c) 2025 CSC - IT Center for Science, http://www.csc.fi
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

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicates;

import fi.csc.shibboleth.authn.AuthenticationDiscoveryContext;
import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.shared.collection.Pair;

/**
 * Abstract class for discovery actions.
 */
public abstract class AbstractDiscoveryExtractionAction extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractDiscoveryExtractionAction.class);

    /** Attribute name of selected flow. */
    protected final static String FLOW_ATTRIBUTE = "fi.csc.shibboleth.authn.discovery.selectedFlow";

    /** Attribute name of selected authority. */
    protected final static String AUTHORITY_ATTRIBUTE = "fi.csc.shibboleth.authn.discovery.selectedAuthority";

    /** Authentication flow selected by the user. */
    protected String flow;

    /** Authority selected by the user. */
    protected String authority;

    /** Discovery context containing valid flow / authority pairs. */
    protected AuthenticationDiscoveryContext discoveryContext;

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        discoveryContext = authenticationContext.ensureSubcontext(AuthenticationDiscoveryContext.class);
        return true;
    }

    /**
     * Validates the user selection matches the listed options.
     *
     * @return true if select matched listed options.
     */
    protected boolean validateUserSelection() {
        for (final Pair<String, String> pair : discoveryContext.getFlowsWithAuthorities()) {
            String configuredAuthority = pair.getSecond();
            if (flow.equals(pair.getFirst())) {
                if (authority == null && configuredAuthority == null) {
                    return true;
                }
                if (configuredAuthority != null) {
                    try {
                        configuredAuthority = java.net.URLDecoder.decode(configuredAuthority,
                                StandardCharsets.UTF_8.name());
                        if (configuredAuthority.equals(authority)) {
                            return true;
                        }
                    } catch (final UnsupportedEncodingException e) {
                        log.error("{} Failed url decoding string", getLogPrefix(), e);
                        // Just move to next one
                    }
                }
            }
        }
        return false;
    }

    /**
     * Signals the next flow to be executed.
     * 
     * @param profileRequestContext Profile request context.
     * @param authenticationContext Authentication context.
     */
    protected void signalNextFlow(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        authenticationContext.setSignaledFlowId(flow);
        final AuthenticationResult result = new AuthenticationResult(flow, new Subject());
        result.setReuseCondition(Predicates.alwaysFalse());
        authenticationContext.getActiveResults().put(flow, result);
        if (authority != null && !authority.isEmpty()) {
            authenticationContext.setAuthenticatingAuthority(authority);
        }
        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.RESELECT_FLOW);
    }
}
