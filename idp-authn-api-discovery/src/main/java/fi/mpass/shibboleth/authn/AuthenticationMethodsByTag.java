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

/**
 * This class constains a name/tag and a list of {@link AuthenticationMethodDescriptor} related to it.
 */
public class AuthenticationMethodsByTag {
    
    /** The name for the set of authentication methods. */
    private AuthenticationMethodsTagDescriptor tag;
    
    /** The list of authentication methods related to the tag. */
    private List<AuthenticationMethodDescriptor> methods;
    
    public AuthenticationMethodsByTag() {
        methods = new ArrayList<>();
    }

    /**
     * Get the name for the set of authentication methods.
     * @return The name for the set of authentication methods.
     */
    public AuthenticationMethodsTagDescriptor getTag() {
        return tag;
    }

    /**
     * Set the name for the set of authentication methods.
     * @param name What to set.
     */
    public void setTag(AuthenticationMethodsTagDescriptor name) {
        this.tag = name;
    }

    /**
     * Get the list of authentication methods related to the tag.
     * @return The list of authentication methods related to the tag.
     */
    public List<AuthenticationMethodDescriptor> getMethods() {
        return methods;
    }

    /**
     * Set the list of authentication methods related to the tag.
     * @param methodDescriptors What to set.
     */
    public void setMethods(List<AuthenticationMethodDescriptor> methodDescriptors) {
        this.methods = methodDescriptors;
    }

}
