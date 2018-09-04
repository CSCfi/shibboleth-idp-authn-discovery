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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.AuthenticationDiscoveryContext;
import fi.mpass.shibboleth.authn.AuthenticationMethodDescriptor;
import fi.mpass.shibboleth.authn.AuthenticationMethodsByTag;
import fi.mpass.shibboleth.authn.AuthenticationMethodsTagDescriptor;
import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This actions populates {@link AuthenticationDiscoveryContext} and attaches it as a subcontext of
 * {@link AuthenticationContext}.
 */
public class PopulateDiscoveryContext extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(PopulateDiscoveryContext.class);

    /** The prefix for the tags in the authentication context class references. */
    private String tagPrefix;

    /** The list of flow ids to be ignored from the discovey context. */
    private List<String> ignoredFlows;

    /** The complementary information for the authentication flows. */
    private Properties additionalInfo;

    /**
     * Constructor.
     */
    public PopulateDiscoveryContext() {
        ignoredFlows = Collections.emptyList();
        setTagPrefix(AuthenticationDiscoveryContext.TAG_PRINCIPAL_PREFIX);
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (additionalInfo == null) {
            throw new ComponentInitializationException("The additional info cannot be null");
        }
    }

    /**
     * Set the complementary information for the authentication flows.
     * 
     * @param properties What to set.
     */
    public void setAdditionalInfo(final Properties properties) {
        additionalInfo = Constraint.isNotNull(properties, "The additional info properties cannot be null!");
    }

    /**
     * Set the prefix for the tags in the authentication context class references.
     * 
     * @param prefix What to set.
     */
    public void setTagPrefix(final String prefix) {
        tagPrefix = Constraint.isNotEmpty(prefix, "The tagPrefix cannot be empty");
    }

    /**
     * Set the list of flow ids to be ignored from the discovey context.
     * 
     * @param flowIds What to set.
     */
    public void setIgnoredFlows(final List<String> flowIds) {
        ignoredFlows = flowIds;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final Map<String, AuthenticationFlowDescriptor> flows = authenticationContext.getPotentialFlows();
        final RequestedPrincipalContext principalContext =
                authenticationContext.getSubcontext(RequestedPrincipalContext.class);
        final List<Principal> requestedPrincipals =
                (principalContext == null) ? new ArrayList<Principal>() : principalContext.getRequestedPrincipals();

        final AuthenticationDiscoveryContext discoveryContext =
                authenticationContext.getSubcontext(AuthenticationDiscoveryContext.class, true);

        discoveryContext.getMethodsByTag().clear();
        final List<AuthenticationMethodsByTag> methodsByTag = discoveryContext.getMethodsByTag();

        for (final String key : flows.keySet()) {
            if (ignoredFlows.contains(key)) {
                log.debug("{} Ignoring {} from the context", getLogPrefix(), key);
            } else {
                final AuthenticationFlowDescriptor flow = flows.get(key);
                final Collection<Principal> principals = flow.getSupportedPrincipals();
                if (isRequestedPrincipal(principals, requestedPrincipals)) {
                    for (final Principal principal : principals) {
                        final String name = principal.getName();
                        if (name.startsWith(tagPrefix)) {
                            final String tag = name.substring(tagPrefix.length());
                            log.debug("{} Found tag {} for flow {}", getLogPrefix(), tag, key);
                            final AuthenticationMethodsByTag taggedMethods = getMethodByTag(methodsByTag, tag);
                            final AuthenticationMethodDescriptor method = new AuthenticationMethodDescriptor();
                            method.setId(flow.getId());
                            final String id =
                                    flow.getId().substring(AuthenticationFlowDescriptor.FLOW_ID_PREFIX.length());
                            method.setTitle(additionalInfo.getProperty(id + "." + tag + ".title") != null
                                    ? additionalInfo.getProperty(id + "." + tag + ".title")
                                    : additionalInfo.getProperty(id + ".title", id + ".title"));
                            method.setStyle(additionalInfo.getProperty(id + "." + tag + ".style") != null
                                    ? additionalInfo.getProperty(id + "." + tag + ".style")
                                    : additionalInfo.getProperty(id + ".style", id + ".style"));
                            taggedMethods.getMethods().add(method);
                        } else {
                            log.debug("{} Ignoring {} from flow {}", getLogPrefix(), principal.getName(), key);
                        }
                    }
                }
            }
        }
    }

    /**
     * Gets the list of authentication methods for one tag from the given list of them for all tags. A new entry will be
     * created to the list for all tags if it was not found.
     * 
     * @param methodsByTag The list of all authentication methods for all tags.
     * @param tag The tag's identifier whose authentication methods are fetched.
     * @return The list of authentication methods for the given tag.
     */
    protected @Nonnull AuthenticationMethodsByTag getMethodByTag(final List<AuthenticationMethodsByTag> methodsByTag,
            final String tag) {
        for (final AuthenticationMethodsByTag methodByTag : methodsByTag) {
            if (methodByTag.getTag().getId().equals(tag)) {
                return methodByTag;
            }
        }
        final AuthenticationMethodsByTag newItem = new AuthenticationMethodsByTag();
        final AuthenticationMethodsTagDescriptor tagDescriptor = new AuthenticationMethodsTagDescriptor();
        tagDescriptor.setId(tag);
        tagDescriptor.setTitle(additionalInfo.getProperty(tag + ".title", tag + ".title"));
        newItem.setTag(tagDescriptor);
        methodsByTag.add(newItem);
        return newItem;
    }

    /**
     * Checks if any of the requested principals are found from the list of supported principals.
     * 
     * @param supportedPrincipals The list of supported principals.
     * @param requestedPrincipals The list of requested principals.
     * @return {@link true} if any of the requested principals were found (or the list of requested principals was
     *         empty), {@link false} otherwise.
     */
    protected boolean isRequestedPrincipal(final Collection<Principal> supportedPrincipals,
            final Collection<Principal> requestedPrincipals) {
        if (requestedPrincipals.isEmpty()) {
            return true;
        }
        for (final Principal principal : requestedPrincipals) {
            if (supportedPrincipals.contains(principal)) {
                return true;
            }
        }
        return false;
    }
}
