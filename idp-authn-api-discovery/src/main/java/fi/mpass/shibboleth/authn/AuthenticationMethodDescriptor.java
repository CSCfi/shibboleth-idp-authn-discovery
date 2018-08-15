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
 * This class contains information about one authentication method needed for visualizing it in the discovery page.
 */
public class AuthenticationMethodDescriptor {
    
    /** The identifier for this method. */
    private String id;

    /** The title reference for this method. */
    private String title;
    
    /** The style reference for this method. */
    private String style;

    /**
     * Get the identifier for this method.
     * @return The identifier for this method.
     */
    public String getId() {
        return id;
    }

    /**
     * Set the identifier for this method.
     * @param newId What to set.
     */
    public void setId(String newId) {
        this.id = newId;
    }

    /**
     * Get the title reference for this method.
     * @return The title reference for this method.
     */
    public String getTitle() {
        return title;
    }

    /**
     * Set the title reference for this method.
     * @param newTitle What to set.
     */
    public void setTitle(String newTitle) {
        this.title = newTitle;
    }

    /** 
     * Get the style reference for this method.
     * @return The style reference for this method.
     */
    public String getStyle() {
        return style;
    }

    /**
     * Set the style reference for this method.
     * @param newStyle What to set.
     */
    public void setStyle(String newStyle) {
        this.style = newStyle;
    }

}