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
package fi.csc.shibboleth.authn.conf;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.annotation.Nonnull;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.shibboleth.shared.annotation.constraint.NotEmpty;

public class DiscoveryConfiguration {

    /** Flow information keyed by relying party. */
    @Nonnull
    @NotEmpty
    private final Map<String, DiscoveryFlows> relyingPartiesAndFlows;

    private DiscoveryConfiguration(@Nonnull @NotEmpty Map<String, DiscoveryFlows> relyingPartiesAndFlows) {
        if (relyingPartiesAndFlows == null || relyingPartiesAndFlows.isEmpty()) {
            throw new IllegalArgumentException("relyingPartiesAndFlows must not be null or empty");
        }
        this.relyingPartiesAndFlows = relyingPartiesAndFlows;
    }

    /**
     * Get flow information keyed by relying party.
     * 
     * @return Flow information keyed by relying party
     */
    public Map<String, DiscoveryFlows> getFlowMap() {
        return relyingPartiesAndFlows;
    }

    /**
     * Parses DiscoveryConfiguration object from JSON string.
     * 
     * @param relyingPartiesAndFlows DiscoveryConfiguration object as JSON string
     * @return DiscoveryConfiguration instance
     * @throws Exception thrown if something unexpected occurs
     */
    @Nonnull
    public static DiscoveryConfiguration parse(String relyingPartiesAndFlows) throws Exception {
        return parse(new ObjectMapper().readValue(relyingPartiesAndFlows, new TypeReference<Map<String, Object>>() {
        }));
    }

    /**
     * Parses DiscoveryConfiguration object from map.
     * 
     * @param object Object that is expected to be type Map<?, ?> representing
     *               DiscoveryConfiguration object.
     * @return DiscoveryConfiguration instance
     * @throws Exception
     */
    @Nonnull
    public static DiscoveryConfiguration parse(Object object) throws Exception {
        if (object instanceof Map<?, ?> flowsPerRelyingParty) {
            Map<String, DiscoveryFlows> relyingPartiesAndFlows = new HashMap<String, DiscoveryFlows>();
            for (Entry<?, ?> entry : flowsPerRelyingParty.entrySet()) {
                if (!(entry.getKey() instanceof String)) {
                    throw new Exception("Invalid key: Parsing failed");
                }
                relyingPartiesAndFlows.put((String) entry.getKey(), DiscoveryFlows.parse(entry.getValue()));
            }
            return new DiscoveryConfiguration(relyingPartiesAndFlows);
        }
        throw new Exception("Invalid flows field: Parsing failed");
    }
}
