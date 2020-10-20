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

package fi.mpass.shibboleth.authn.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.AuthenticationDiscoveryContext;
import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * This actions populates {@link AuthenticationDiscoveryContext} and attaches it as a subcontext of
 * {@link AuthenticationContext}.
 */
public class PopulateDiscoveryContext extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(PopulateDiscoveryContext.class);

    /** The list of flow ids to be ignored from the discovery context. */
    private List<String> ignoredFlows;
    
    private Properties authorityProperties;

    /**
     * Constructor.
     */
    public PopulateDiscoveryContext() {
        ignoredFlows = Collections.emptyList();
        authorityProperties = new Properties();
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
    }

    /**
     * Set the list of flow ids to be ignored from the discovey context.
     * 
     * @param flowIds What to set.
     */
    public void setIgnoredFlows(final List<String> flowIds) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ignoredFlows = Constraint.isNotNull(flowIds, "List of ignored flow ids cannot be null");
    }
    
    public void setAuthorityProperties(final String propertiesFile) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        if (StringSupport.trimOrNull(propertiesFile) == null) {
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

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final Map<String, AuthenticationFlowDescriptor> flows = authenticationContext.getPotentialFlows();
        final AuthenticationDiscoveryContext discoveryContext = new AuthenticationDiscoveryContext();

        for (final String key : flows.keySet()) {
            if (ignoredFlows.contains(key)) {
                log.debug("{} Ignoring {} from the context", getLogPrefix(), key);
            } else {
                final AuthenticationFlowDescriptor flow = flows.get(key);
                final String authorities = (String) authorityProperties.get(flow.getId());
                if (StringSupport.trimOrNull(authorities) != null) {
                    for (final String authority : authorities.split(",")) {
                        discoveryContext.getFlowsWithAuthorities().add(new Pair<>(flow.getId(), authority));
                    }
                } else {
                    discoveryContext.getFlowsWithAuthorities().add(new Pair<>(flow.getId(), null));
                }
            }
        }
        authenticationContext.addSubcontext(discoveryContext, true);
    }
}
