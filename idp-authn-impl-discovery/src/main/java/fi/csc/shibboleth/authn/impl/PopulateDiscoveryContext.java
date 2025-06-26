/*
 * The MIT License
 * Copyright (c) 2015-2025 CSC - IT Center for Science, http://www.csc.fi
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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.Function;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;

import fi.csc.shibboleth.authn.AuthenticationDiscoveryContext;
import fi.csc.shibboleth.authn.conf.DiscoveryConfiguration;
import fi.csc.shibboleth.authn.conf.DiscoveryFlows;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.shared.collection.Pair;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;

/**
 * 
 * This actions populates {@link AuthenticationDiscoveryContext} and attaches it
 * as a subcontext of {@link AuthenticationContext}.
 * 
 * If a user selections can be extracted from session it is set as signaled
 * authentication flow in {@link AuthenticationContext}. The signaled flow is
 * set without any validations: it is assumed that the upcoming actions (like
 * for instance the default {@link SelectAuthenticationFlow}) verifies whether
 * the signaled flow meets the requirements in the context. Finally, the action
 * builds {@link AuthnEventIds.RESELECT_FLOW} event.
 *
 * If the action extracts not only flow but also Authenticating Authority the
 * values must match flow authority pair defined in
 * {@link AuthenticationDiscoveryContext}.
 *
 * @event {@link AuthnEventIds#REQUEST_UNSUPPORTED}
 * @event {@link AuthnEventIds#RESELECT_FLOW}
 * @pre
 * 
 *      <pre>
 *      ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null
 *      </pre>
 */
public class PopulateDiscoveryContext extends AbstractDiscoveryExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(PopulateDiscoveryContext.class);

    /** The list of flow ids to be ignored from the discovery context. */
    private List<String> ignoredFlows;

    /** Properties having list of authenticating authorities per flow. */
    @Nullable
    private Properties authorityProperties;

    /** JSON initialized alternative configuration to authorityProperties. */
    @Nullable
    private DiscoveryConfiguration authorityConfiguration;

    /** Relying party id. */
    private String relyingPartyId;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a
     * given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /**
     * Constructor.
     */
    public PopulateDiscoveryContext() {
        ignoredFlows = Collections.emptyList();
        authorityProperties = new Properties();
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
    }

    /**
     * Set the list of flow ids to be ignored from the discovey context.
     *
     * @param flowIds What to set.
     */
    public void setIgnoredFlows(final List<String> flowIds) {
        checkSetterPreconditions();
        ignoredFlows = Constraint.isNotNull(flowIds, "List of ignored flow ids cannot be null");
    }

    /**
     * Set filename of authenticating authorities property file.
     * 
     * @param propertiesFile Filename of authenticating authorities property file
     */
    public void setAuthorityProperties(@Nullable final String propertiesFile) {
        checkSetterPreconditions();
        if (propertiesFile == null || propertiesFile.isEmpty()) {
            log.debug("{} No authority properties configured", getLogPrefix());
        } else {
            log.debug("{} Reading authority properties from {}", getLogPrefix(), propertiesFile);
            authorityProperties = new Properties();
            try {
                final InputStream stream = new FileInputStream(propertiesFile);
                authorityProperties.load(stream);
            } catch (final IOException e) {
                log.error("{} Error loading {}", getLogPrefix(), propertiesFile, e);
            }
        }
    }
    
    /**
     * Set JSON based alternative configuration to authorityProperties.
     * @param authorities JSON based alternative configuration to authorityProperties
     */
    public void setAuthorities(String authorities) {
        if (authorities != null && !authorities.isBlank()) {
            try {
                authorityConfiguration = DiscoveryConfiguration.parse(authorities);
            } catch (Exception e) {
                log.error("{} Failed parsing {}", getLogPrefix(), authorities, e);
            }
        }
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated
     * with a given {@link ProfileRequestContext}.
     *
     * @param strategy strategy used to locate the {@link RelyingPartyContext}
     *                 associated with a given {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        checkSetterPreconditions();

        relyingPartyContextLookupStrategy = Constraint.isNotNull(strategy,
                "RelyingPartyContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final RelyingPartyContext rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.error("{} No relying party context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        relyingPartyId = rpCtx.getRelyingPartyId();
        return super.doPreExecute(profileRequestContext, authenticationContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final Map<String, AuthenticationFlowDescriptor> flows = authenticationContext.getPotentialFlows();
        for (final String key : flows.keySet()) {
            if (ignoredFlows.contains(key)) {
                log.debug("{} Ignoring {} from the context", getLogPrefix(), key);
            } else if (authorityConfiguration == null){
                final AuthenticationFlowDescriptor flow = flows.get(key);
                String authorities = null;
                if (relyingPartyId != null) {
                    authorities = (String) authorityProperties.get(relyingPartyId + "." + flow.getId());
                }
                if (authorities == null || authorities.isEmpty()) {
                    authorities = (String) authorityProperties.get(flow.getId());
                }
                if (authorities != null && !authorities.isEmpty()) {
                    for (final String authority : authorities.split(",")) {
                        discoveryContext.getFlowsWithAuthorities().add(new Pair<>(flow.getId(), authority.trim()));
                    }
                } else {
                    discoveryContext.getFlowsWithAuthorities().add(new Pair<>(flow.getId(), null));
                }
            }else {
                //TODO refactor if - else.
                final AuthenticationFlowDescriptor flow = flows.get(key);
                DiscoveryFlows rpConf = authorityConfiguration.getFlowMap().containsKey(relyingPartyId)
                        ? authorityConfiguration.getFlowMap().get(relyingPartyId)
                        : authorityConfiguration.getFlowMap().get("default");
                if (rpConf.getAuthorityMap().containsKey(flow.getId())) {
                    rpConf.getAuthorityMap().get(flow.getId()).forEach(authority -> {
                        try {
                            String authorityValue = authority.toB64UrlEncoded();
                            log.info("{} Setting authority as {}", getLogPrefix(), authorityValue);
                            discoveryContext.getFlowsWithAuthorities().add(new Pair<>(flow.getId(), authorityValue));
                        } catch (JsonProcessingException e) {
                            log.error("{} Processing exception",getLogPrefix(),e);
                        }
                    });
                }else {
                    discoveryContext.getFlowsWithAuthorities().add(new Pair<>(flow.getId(), null));
                }
                
            }
        }

        // Look for prior selection
        flow = (String) getHttpServletRequest().getSession().getAttribute(FLOW_ATTRIBUTE);
        authority = (String) getHttpServletRequest().getSession().getAttribute(AUTHORITY_ATTRIBUTE);

        if (flow == null || flow.isBlank()) {
            return;
        }
        if (!validateUserSelection()) {
            log.debug("{} Prior selection {} {} does not match configured selections", getLogPrefix(), flow, authority);
            return;
        }
        log.info("{} User has prior selection {} {}", getLogPrefix(), flow, authority);
        signalNextFlow(profileRequestContext, authenticationContext);

    }

}
