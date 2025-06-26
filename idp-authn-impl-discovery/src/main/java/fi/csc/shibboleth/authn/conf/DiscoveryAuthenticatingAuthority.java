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

import java.util.Base64;
import java.util.Iterator;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.shibboleth.shared.annotation.constraint.NotEmpty;

/**
 * Class is responsible of serializing and de-serializing Discovery
 * Authentication Authority JSON Object. Object has three string fields:
 * 
 * acr : Voluntary information for scripts indicating which acr value should be
 * used for discovery selection. aaType : Voluntary information for scripts
 * indicating type of the authenticating authority, for instance "issuer",
 * "discovery" or "entity". aaValue : Mandatory information for scripts
 * indicating value of authenticating authority, for instance issuer value,
 * discovery url or entity id.
 * 
 */
public class DiscoveryAuthenticatingAuthority {

    /** Key of acr value. */
    public final static String ACR_KEY = "acr";

    /** Key of Authenticating Authority Type. */
    public final static String AA_TYPE_KEY = "aaType";

    /** Key of Authenticating Authority Value. */
    public final static String AA_VALUE_KEY = "aaValue";

    /** Authenticating authority acr. */
    @Nullable
    @JsonProperty(ACR_KEY)
    private final String acr;

    /** Authenticating authority type. */
    @Nullable
    @JsonProperty(AA_TYPE_KEY)
    private final String type;

    /** Authenticating authority value. */
    @Nonnull
    @JsonProperty(AA_VALUE_KEY)
    private final String value;

    /**
     * Constructor.
     * 
     * @param acr   Authenticating authority acr
     * @param type  Authenticating authority type
     * @param value Authenticating authority value
     */
    private DiscoveryAuthenticatingAuthority(@Nullable String acr, @Nullable String type, @Nonnull String value) {
        this.acr = acr;
        this.type = type;
        this.value = value;
        assert value != null;
    }

    /**
     * Get authenticating authority acr.
     * 
     * @return Authenticating authority acr
     */
    @Nullable
    public String getAcr() {
        return acr;
    }

    /**
     * Get authenticating authority type.
     * 
     * @return Authenticating authority type
     */
    @Nullable
    public String getType() {
        return type;
    }

    /**
     * Get authenticating authority value.
     * 
     * @return Authenticating authority value
     */
    @Nonnull
    public String getValue() {
        return value;
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
        return new ObjectMapper().writeValueAsString(this);
    }

    /**
     * Serializes object to B64 url encoded JSON string.
     * 
     * @return object as B64 url encoded JSON string
     * @throws JsonProcessingException thrown if something unexpected occurs.
     */
    public String toB64UrlEncoded() throws JsonProcessingException {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(toJSON().getBytes());
    }

    /**
     * Parses DiscoveryAuthenticatingAuthority object from B64 url encoded JSON
     * string.
     * 
     * @param discoveryAuthenticatingAuthority DiscoveryAuthenticatingAuthority as
     *                                         B64 url encoded JSON string
     * @return DiscoveryAuthenticatingAuthority instance
     * @throws Exception thrown if something unexpected occurs
     */
    @Nonnull
    public static DiscoveryAuthenticatingAuthority parseB64UrlEncoded(String discoveryAuthenticatingAuthority)
            throws Exception {
        return parse(new String(Base64.getUrlDecoder().decode(discoveryAuthenticatingAuthority.getBytes())));
    }

    /**
     * Parses DiscoveryAuthenticatingAuthority object from JSON string.
     * 
     * @param discoveryAuthenticatingAuthority DiscoveryAuthenticatingAuthority as
     *                                         JSON string
     * @return DiscoveryAuthenticatingAuthority instance
     * @throws Exception thrown if something unexpected occurs
     */
    @Nonnull
    public static DiscoveryAuthenticatingAuthority parse(String discoveryAuthenticatingAuthority) throws Exception {
        return parse(new ObjectMapper().readValue(discoveryAuthenticatingAuthority,
                new TypeReference<Map<String, Object>>() {
                }));
    }

    /**
     * Parses DiscoveryAuthenticatingAuthority object from map.
     * 
     * @param object Object that is expected to be type Map<?, ?> representing
     *               DiscoveryAuthenticatingAuthority object.
     * @return DiscoveryAuthenticatingAuthority instance
     * @throws Exception
     */
    @Nonnull
    public static DiscoveryAuthenticatingAuthority parse(Object object) throws Exception {
        if (object instanceof Map<?, ?> authenticatingAuthority) {
            String acr = (authenticatingAuthority.get(ACR_KEY) instanceof String)
                    ? (String) (authenticatingAuthority.get(ACR_KEY))
                    : null;
            String type = (authenticatingAuthority.get(AA_TYPE_KEY) instanceof String)
                    ? (String) (authenticatingAuthority.get(AA_TYPE_KEY))
                    : null;
            String value = (authenticatingAuthority.get(AA_VALUE_KEY) instanceof String)
                    ? (String) (authenticatingAuthority.get(AA_VALUE_KEY))
                    : null;
            return new DiscoveryAuthenticatingAuthority(acr, type, value);
        }
        throw new Exception("Invalid credential offer requested claim: Parsing failed");
    }

    
    //hmm.. Move this to strategy that resolves relying parties and all..strategy is beaned in our global!
    public static DiscoveryAuthenticatingAuthority resolveAuthenticatingAuthorityFromDiscoveryConfiguration(
            @Nonnull @NotEmpty String relyingPartiesAndFlows, @Nonnull @NotEmpty String rpId,
            @Nonnull @NotEmpty String acr) throws Exception {

        assert relyingPartiesAndFlows != null;
        assert !relyingPartiesAndFlows.isBlank();
        assert rpId != null;
        assert !rpId.isBlank();
        assert acr != null;
        assert !acr.isBlank();
        
        DiscoveryConfiguration configuration = DiscoveryConfiguration.parse(relyingPartiesAndFlows);
        DiscoveryFlows discoveryFlows = configuration.getFlowMap().containsKey(rpId)
                ? configuration.getFlowMap().get(rpId)
                : configuration.getFlowMap().get("default");
        Iterator<String> flows = discoveryFlows.getAuthorityMap().keySet().iterator();
        while (flows.hasNext()) {
            String flow = flows.next();
            Iterator<DiscoveryAuthenticatingAuthority> authorities = discoveryFlows.getAuthorityMap().get(flow)
                    .iterator();
            while (authorities.hasNext()) {
                DiscoveryAuthenticatingAuthority authority = authorities.next();
                if (acr.equals(authority.getAcr())) {
                    return authority;
                }
            }
        }
        return null;
    }
}
