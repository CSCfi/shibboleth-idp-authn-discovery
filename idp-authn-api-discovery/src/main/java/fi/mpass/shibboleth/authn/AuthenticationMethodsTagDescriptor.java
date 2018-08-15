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

/**
 * This class contains information for a tag for a set of authentication methods.
 */
public class AuthenticationMethodsTagDescriptor {
    
    /** The identifier for this tag. */
    private String id;
    
    /** The title reference for this tag. */
    private String title;

    /**
     * Get the identifier for this tag.
     * @return The identifier for this tag.
     */
    public String getId() {
        return id;
    }

    /**
     * Set the identifier for this tag.
     * @param identifier What to set.
     */
    public void setId(String identifier) {
        this.id = identifier;
    }

    /**
     * Get the title reference for this tag.
     * @return The title reference for this tag.
     */
    public String getTitle() {
        return title;
    }

    /**
     * Set the title reference for this tag.
     * @param newTitle What to set.
     */
    public void setTitle(String newTitle) {
        this.title = newTitle;
    }
    
    

}
