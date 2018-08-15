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

package fi.mpass.shibboleth.authn;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.BaseContext;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This class carries information for the authentication method discovery about the potential authentication flows.
 */
public class AuthenticationDiscoveryContext extends BaseContext {
    
    /** The prefix for the principal names used in the ACRs. */
    public static final String PRINCIPAL_PREFIX = "urn:mpass.id:";

    /** The prefix for the source principal names used in the ACRs. */
    public static final String SOURCE_PRINCIPAL_PREFIX = PRINCIPAL_PREFIX + "authnsource:";

    /** The prefix for the tag principal names used in the ACRs. */
    public static final String TAG_PRINCIPAL_PREFIX = PRINCIPAL_PREFIX + "authntag:";
    
    /** The list of authentication methods by their tag. */
    private List<AuthenticationMethodsByTag> methodsByTag;
    
    /**
     * Constructor.
     */
    public AuthenticationDiscoveryContext() {
        methodsByTag = new ArrayList<>();
    }
    
    /**
     * Get the list of authentication methods by their tag.
     * @return The list of authentication methods by their tag.
     */
    public @Nonnull List<AuthenticationMethodsByTag> getMethodsByTag() {
        return methodsByTag;
    }
    
    /**
     * Set the list of authentication methods by their tag.
     * @param methods What to set.
     */
    public void setMethodsByTag(@Nonnull List<AuthenticationMethodsByTag> methods) {
        methodsByTag = Constraint.isNotNull(methods, "The methods by tag list cannot be null!");
    }
}