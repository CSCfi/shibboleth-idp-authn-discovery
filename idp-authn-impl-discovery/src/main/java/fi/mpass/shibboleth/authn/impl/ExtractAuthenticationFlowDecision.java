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

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that extracts a selected authentication flow from an HTTP form body or query string
 * and sets it as signaled authentication flow in {@link AuthenticationContext}. The signaled flow is
 * set without any validations: it is assumed that the upcoming actions (like for instance the default
 * {@link SelectAuthenticationFlow}) verifies whether the signaled flow meets the requirements in the
 * context. Finally, the action builds {@link AuthnEventIds.RESELECT_FLOW} event.
 * 
 * @event {@link AuthnEventIds#REQUEST_UNSUPPORTED}
 * @event {@link AuthnEventIds#RESELECT_FLOW}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 */
@SuppressWarnings("rawtypes")
public class ExtractAuthenticationFlowDecision extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ExtractAuthenticationFlowDecision.class);

    /** Parameter name for authentication flow id. */
    @Nonnull @NotEmpty private String authnFlowFieldName;
    
    /** Parameter name for selected authentication detail to be put to authentication state map. */
    private String selectedAuthnFieldName;
    
    /** Authentication state map key name for the selected authentication detail. */
    private String selectedAuthnStateKey;
    
    /**
     * Set the authnFlow parameter name.
     * 
     * @param fieldName the authnFlow parameter name
     */
    public void setAuthnFlowFieldName(@Nonnull @NotEmpty final String fieldName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        authnFlowFieldName = Constraint.isNotNull(
                StringSupport.trimOrNull(fieldName), "AuthnFlow field name cannot be null or empty.");
    }
    
    /**
     * Set the parameter name for selected authentication detail to be put to authentication state map.
     * @param fieldName What to set.
     */
    public void setSelectedAuthnFieldName(final String fieldName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        selectedAuthnFieldName = fieldName;
    }
    
    /**
     * Set the authentication state map key name for the selected authentication detail.
     * @param keyName What to set.
     */
    public void setSelectedAuthnStateKey(final String keyName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        selectedAuthnStateKey = keyName;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.REQUEST_UNSUPPORTED);
            return;
        }
        
        final String authnFlow = request.getParameter(authnFlowFieldName);
        if (StringSupport.trimOrNull(authnFlow) == null) {
            log.debug("{} No authnFlow in request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.REQUEST_UNSUPPORTED);
            return;
        }
        log.debug("{} User selected authnFlow {}", getLogPrefix(), authnFlow);
        authenticationContext.setSignaledFlowId(authnFlow);
        if (selectedAuthnFieldName != null && selectedAuthnStateKey != null) {
            final String selectedAuthn = request.getParameter(selectedAuthnFieldName);
            if (StringSupport.trimOrNull(selectedAuthn) != null) {
                authenticationContext.getAuthenticationStateMap().put(selectedAuthnStateKey, selectedAuthn);
                log.debug("{} Selected authentication detail set to {} as parameter {}", 
                        getLogPrefix(), selectedAuthn, selectedAuthnStateKey);
            }
        }
        ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.RESELECT_FLOW);
    }   
}