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

import javax.annotation.Nonnull;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.csc.shibboleth.authn.AuthenticationDiscoveryContext;
import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.logic.Constraint;

/**
 * An action that extracts a selected authentication flow from an HTTP form body
 * or query string and sets it as signaled authentication flow in
 * {@link AuthenticationContext}. The signaled flow is set without any
 * validations: it is assumed that the upcoming actions (like for instance the
 * default {@link SelectAuthenticationFlow}) verifies whether the signaled flow
 * meets the requirements in the context. Finally, the action builds
 * {@link AuthnEventIds.RESELECT_FLOW} event.
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
public class ExtractAuthenticationFlowDecision extends AbstractDiscoveryExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ExtractAuthenticationFlowDecision.class);

    /** Parameter name for authentication flow id. */
    @Nonnull
    @NotEmpty
    private String authnFlowFieldName;

    /** Parameter name for selected authentication authority. */
    private String selectedAuthorityFieldName;

    /** Whether to store user selection to session. */
    private boolean storeSelection;

    /**
     * Set the authnFlow parameter name.
     *
     * @param fieldName the authnFlow parameter name
     */
    public void setAuthnFlowFieldName(@Nonnull @NotEmpty final String fieldName) {
        checkSetterPreconditions();
        authnFlowFieldName = Constraint.isNotEmpty(fieldName, "AuthnFlow field name cannot be null or empty.");
    }

    /**
     * Set the parameter name for selected authentication detail to be put to
     * authentication state map.
     * 
     * @param fieldName What to set.
     */
    public void setSelectedAuthorityFieldName(final String fieldName) {
        checkSetterPreconditions();
        selectedAuthorityFieldName = fieldName;
    }

    /**
     * Set whether to store user selection to session.
     * 
     * @param store Whether to store user selection to session
     */
    public void setStoreSelection(final boolean store) {
        checkSetterPreconditions();
        storeSelection = store;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.error("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.REQUEST_UNSUPPORTED);
            return false;
        }
        flow = request.getParameter(authnFlowFieldName);
        if (flow == null || flow.isEmpty()) {
            log.error("{} No authnFlow in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.REQUEST_UNSUPPORTED);
            return false;
        }
        flow = applyTransforms(flow);
        if (selectedAuthorityFieldName != null && request.getParameter(selectedAuthorityFieldName) != null) {
            authority = applyTransforms(request.getParameter(selectedAuthorityFieldName));
        }
        return super.doPreExecute(profileRequestContext, authenticationContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!validateUserSelection()) {
            log.error("{} Extracted user selections did not match provided ones", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.REQUEST_UNSUPPORTED);
            return;
        }
        log.info("{} User selected {} {}", getLogPrefix(), flow, authority);
        if (storeSelection) {
            getHttpServletRequest().getSession().setAttribute(FLOW_ATTRIBUTE, flow);
            getHttpServletRequest().getSession().setAttribute(AUTHORITY_ATTRIBUTE, authority);
        }
        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.RESELECT_FLOW);
        signalNextFlow(profileRequestContext, authenticationContext);
    }

}