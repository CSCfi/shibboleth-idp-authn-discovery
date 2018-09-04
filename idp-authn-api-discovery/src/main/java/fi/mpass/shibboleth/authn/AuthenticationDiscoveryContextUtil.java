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

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Static utility methods related to {@link AuthenticationDiscoveryContext}.
 */
public class AuthenticationDiscoveryContextUtil {

    /**
     * Sort the methods from the given list of {@link AuthenticationMethodsByTag} by
     * {@link AuthenticationMethodDescriptor#getTitle()}.
     * 
     * @param methodsByTags The list whose methods are to be sorted.
     * @return The sorted list.
     */
    public static List<AuthenticationMethodsByTag> sortByTitle(final List<AuthenticationMethodsByTag> methodsByTags) {
        for (final AuthenticationMethodsByTag methodsByTag : methodsByTags) {
            sortByTitle(methodsByTag);
        }
        return methodsByTags;
    }

    /**
     * Sort the methods from the given {@link AuthenticationMethodsByTag} by
     * {@link AuthenticationMethodDescriptor#getTitle()}.
     * 
     * @param methodsByTag Whose methods are to be sorted.
     * @return The {@link AuthenticationMethodsByTag} containing methods sorted by title.
     */
    public static AuthenticationMethodsByTag sortByTitle(final AuthenticationMethodsByTag methodsByTag) {
        Collections.sort(methodsByTag.getMethods(), new Comparator<AuthenticationMethodDescriptor>() {

            @Override
            public int compare(AuthenticationMethodDescriptor one, AuthenticationMethodDescriptor another) {
                return one.getTitle().compareTo(another.getTitle());
            }

        });
        return methodsByTag;
    }
}
