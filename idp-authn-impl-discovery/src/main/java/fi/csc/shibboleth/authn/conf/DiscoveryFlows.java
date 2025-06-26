/*
 * The MIT License
 * Copyright (c) 2025 CSC - IT Center for Science, http://www.csc.fi
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
package fi.csc.shibboleth.authn.conf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.annotation.Nonnull;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.shibboleth.shared.annotation.constraint.NotEmpty;

/**
 * Class is responsible of serializing and de-serializing
 * {@link DiscoveryAuthenticatingAuthority} per flows JSON Object.
 */
public class DiscoveryFlows {

    /** Authenticating authority information keyed by flows. */
    @Nonnull
    @NotEmpty
    private final Map<String, List<DiscoveryAuthenticatingAuthority>> flowsAndAuthorities;

    /**
     * Constructor.
     * @param flowsAndAuthorities Authenticating authority information keyed by flows
     */
    private DiscoveryFlows(@Nonnull @NotEmpty Map<String, List<DiscoveryAuthenticatingAuthority>> flowsAndAuthorities) {
        if (flowsAndAuthorities == null || flowsAndAuthorities.isEmpty()) {
            throw new IllegalArgumentException("flowsAndAuthorities must not be null or empty");
        }
        this.flowsAndAuthorities = flowsAndAuthorities;
    }

    
    /**
     * Get authenticating authority information keyed by flows.
     * @return Authenticating authority information keyed by flows
     */
    @Nonnull
    @NotEmpty
    public Map<String, List<DiscoveryAuthenticatingAuthority>> getAuthorityMap() {
        return flowsAndAuthorities;
    }

    /**
     * Serializes object to JSON string.
     * 
     * @return object as JSON string
     * @throws JsonProcessingException thrown if something unexpected occurs.
     */
    @Nonnull
    @NotEmpty
    public String toJSON() throws JsonProcessingException {
        return new ObjectMapper().writeValueAsString(this.flowsAndAuthorities);
    }

    
    /**
     * Parses DiscoveryFlows object from JSON string.
     * 
     * @param flowsAndAuthorities DiscoveryFlows object as JSON string
     * @return DiscoveryFlows instance
     * @throws Exception thrown if something unexpected occurs
     */
    @Nonnull
    public static DiscoveryFlows parse(String flowsAndAuthorities) throws Exception {
        return parse(new ObjectMapper().readValue(flowsAndAuthorities, new TypeReference<Map<String, Object>>() {
        }));
    }

    /**
     * Parses DiscoveryFlows object from map.
     * 
     * @param object Object that is expected to be type Map<?, ?> representing
     *               DiscoveryFlows object.
     * @return DiscoveryFlows instance
     * @throws Exception
     */
    @Nonnull
    public static DiscoveryFlows parse(Object object) throws Exception {
        if (object instanceof Map<?, ?> authenticatingAuthoritiesPerFlow) {
            Map<String, List<DiscoveryAuthenticatingAuthority>> path = new HashMap<String, List<DiscoveryAuthenticatingAuthority>>();
            for (Entry<?, ?> entry : authenticatingAuthoritiesPerFlow.entrySet()) {
                if (!(entry.getKey() instanceof String)) {
                    throw new Exception("Invalid key: Parsing failed");
                }
                List<DiscoveryAuthenticatingAuthority> discoveryAuthenticatingAuthorities = new ArrayList<DiscoveryAuthenticatingAuthority>();
                if ((entry.getValue() instanceof List<?> authorities)) {
                    for (Object authority : authorities) {
                        discoveryAuthenticatingAuthorities.add(DiscoveryAuthenticatingAuthority.parse(authority));
                    }

                } else {
                    throw new Exception("Invalid authority information: Parsing failed");
                }
                path.put((String) entry.getKey(), discoveryAuthenticatingAuthorities);
            }
            return new DiscoveryFlows(path);
        }
        throw new Exception("Invalid flows field: Parsing failed");
    }
}
