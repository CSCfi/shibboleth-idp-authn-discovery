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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.security.crypto.SigningUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;

/**
 * Verifies the signature of a JWS in compact serialization and returns its
 * claims. Every configured {@link Credential} whose key type suits the
 * algorithm is tried.
 *
 * <p>
 * Only asymmetric algorithms on the {@link #setSignatureAlgorithms(List)}
 * allow-list are accepted; the {@code alg} header cannot select anything
 * outside it.
 * </p>
 */
public class SignedJWTVerifier extends AbstractInitializableComponent {

    /** JOSE algorithm to JCA signature algorithm. */
    @Nonnull
    private static final Map<String, String> JCA_ALGORITHMS = Map.of("RS256", JCAConstants.SIGNATURE_RSA_SHA256,
            "RS384", JCAConstants.SIGNATURE_RSA_SHA384, "RS512", JCAConstants.SIGNATURE_RSA_SHA512, "ES256",
            "SHA256withECDSAinP1363Format", "ES384", "SHA384withECDSAinP1363Format", "ES512",
            "SHA512withECDSAinP1363Format");

    /** JOSE algorithm to the JCA key algorithm its verification key must have. */
    @Nonnull
    private static final Map<String, String> KEY_ALGORITHMS = Map.of("RS256", JCAConstants.KEY_ALGO_RSA, "RS384",
            JCAConstants.KEY_ALGO_RSA, "RS512", JCAConstants.KEY_ALGO_RSA, "ES256", JCAConstants.KEY_ALGO_EC, "ES384",
            JCAConstants.KEY_ALGO_EC, "ES512", JCAConstants.KEY_ALGO_EC);

    // CheckStyle: ConstantName OFF
    /** JSON mapper. */
    @Nonnull
    private static final ObjectMapper objectMapper = new ObjectMapper();
    // CheckStyle: ConstantName ON

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SignedJWTVerifier.class);

    /** Credentials holding the keys a signature may be verified with. */
    @Nonnull
    private List<Credential> credentials;

    /** JOSE algorithms that are accepted. */
    @Nonnull
    private Set<String> signatureAlgorithms;

    /** Tolerance applied when evaluating the time claims. */
    @Nonnull
    private Duration clockSkew;

    /** Whether a token without an {@code exp} claim is rejected. */
    private boolean requireExpiration;

    /** Constructor. */
    public SignedJWTVerifier() {
        credentials = List.of();
        signatureAlgorithms = JCA_ALGORITHMS.keySet();
        clockSkew = Duration.ofSeconds(30);
    }

    /**
     * Get the JOSE algorithms this verifier is able to handle at all.
     *
     * @return the supported JOSE algorithms
     */
    @Nonnull
    public static Set<String> getSupportedSignatureAlgorithms() {
        return JCA_ALGORITHMS.keySet();
    }

    /**
     * Set the credentials holding the keys a signature may be verified with.
     *
     * @param creds what to set
     */
    public void setCredentials(@Nonnull final List<Credential> creds) {
        checkSetterPreconditions();

        credentials = List.copyOf(Constraint.isNotNull(creds, "Credentials cannot be null"));
    }

    /**
     * Set the JOSE algorithms that are accepted, defaults to
     * {@link #getSupportedSignatureAlgorithms()}.
     *
     * @param algorithms what to set
     */
    public void setSignatureAlgorithms(@Nonnull final List<String> algorithms) {
        checkSetterPreconditions();

        signatureAlgorithms = Set.copyOf(Constraint.isNotNull(algorithms, "Signature algorithms cannot be null"));
    }

    /**
     * Set the tolerance applied to the {@code exp} and {@code nbf} claims, defaults
     * to 30 seconds.
     *
     * @param skew what to set
     */
    public void setClockSkew(@Nonnull final Duration skew) {
        checkSetterPreconditions();

        clockSkew = Constraint.isNotNull(skew, "Clock skew cannot be null");
    }

    /**
     * Set whether a token without an {@code exp} claim is rejected, defaults to
     * false.
     *
     * @param require what to set
     */
    public void setRequireExpiration(final boolean require) {
        checkSetterPreconditions();

        requireExpiration = require;
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (credentials.isEmpty()) {
            throw new ComponentInitializationException("At least one verification credential is required");
        }
        if (signatureAlgorithms.isEmpty()) {
            throw new ComponentInitializationException("At least one signature algorithm is required");
        }
        for (final String algorithm : signatureAlgorithms) {
            if (!JCA_ALGORITHMS.containsKey(algorithm)) {
                throw new ComponentInitializationException("Unsupported signature algorithm '" + algorithm
                        + "', supported are " + JCA_ALGORITHMS.keySet());
            }
        }
    }

    /**
     * Verify a JWS in compact serialization and return its claims.
     *
     * @param jws the JWS to verify
     * @return the claims of the verified token
     * @throws SecurityException if the token is malformed, unacceptably signed, or
     *                           outside its validity window
     */
    @Nonnull
    public Map<String, Object> verify(@Nonnull final byte[] jws) throws SecurityException {
        checkComponentActive();

        final String compact = new String(jws, StandardCharsets.UTF_8).trim();
        final String[] parts = compact.split("\\.", -1);
        if (parts.length != 3) {
            throw new SecurityException(
                    "Not a JWS in compact serialization, expected 3 parts but found " + parts.length);
        }

        final String algorithm = readAlgorithm(parts[0]);
        verifySignature(algorithm, parts);

        final Map<String, Object> claims = decodeJson(parts[1], "payload");
        validateTimeClaims(claims);
        return claims;
    }

    /**
     * Read and vet the {@code alg} header.
     *
     * @param encodedHeader the encoded JOSE header
     * @return the accepted JOSE algorithm
     * @throws SecurityException if the header is unreadable, carries {@code crit},
     *                           or names an unaccepted algorithm
     */
    @Nonnull
    protected String readAlgorithm(@Nonnull final String encodedHeader) throws SecurityException {
        final Map<String, Object> header = decodeJson(encodedHeader, "header");

        if (header.containsKey("crit")) {
            throw new SecurityException("JWS carries a 'crit' header, which is not supported");
        }

        final Object algorithm = header.get("alg");
        if (!(algorithm instanceof String)) {
            throw new SecurityException("JWS header has no usable 'alg'");
        }
        if (!signatureAlgorithms.contains(algorithm)) {
            throw new SecurityException(
                    "JWS algorithm '" + algorithm + "' is not accepted, accepted are " + signatureAlgorithms);
        }
        return (String) algorithm;
    }

    /**
     * Verify the signature against every credential whose key suits the algorithm.
     *
     * @param algorithm the accepted JOSE algorithm
     * @param parts     the three parts of the compact serialization
     * @throws SecurityException if no configured credential verifies the signature
     */
    protected void verifySignature(@Nonnull final String algorithm, @Nonnull final String[] parts)
            throws SecurityException {

        final String jcaAlgorithm = JCA_ALGORITHMS.get(algorithm);
        final String keyAlgorithm = KEY_ALGORITHMS.get(algorithm);
        final byte[] signature = decodeBase64Url(parts[2], "signature");
        final byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);

        boolean anyKeyTried = false;
        for (final Credential credential : credentials) {
            final PublicKey key = credential.getPublicKey();
            if (key == null || !keyAlgorithm.equals(key.getAlgorithm())) {
                continue;
            }
            anyKeyTried = true;
            try {
                if (SigningUtil.verify(credential, jcaAlgorithm, false, signature, signingInput)) {
                    log.debug("JWS signature verified with a {} key using {}", keyAlgorithm, algorithm);
                    return;
                }
            } catch (final SecurityException e) {
                log.debug("Verification with one of the configured credentials failed, trying the next", e);
            }
        }

        if (!anyKeyTried) {
            throw new SecurityException(
                    "No configured credential holds a " + keyAlgorithm + " public key for algorithm " + algorithm);
        }
        throw new SecurityException("JWS signature did not verify against any configured credential");
    }

    /**
     * Reject a token that is expired or not yet valid.
     *
     * @param claims the claims of the token
     * @throws SecurityException if the token is outside its validity window, or
     *                           lacks a required {@code exp}
     */
    protected void validateTimeClaims(@Nonnull final Map<String, Object> claims) throws SecurityException {
        final Instant now = Instant.now();

        final Instant expiration = readTimeClaim(claims, "exp");
        if (expiration == null) {
            if (requireExpiration) {
                throw new SecurityException("JWS has no 'exp' claim");
            }
        } else if (now.minus(clockSkew).isAfter(expiration)) {
            throw new SecurityException("JWS expired at " + expiration);
        }

        final Instant notBefore = readTimeClaim(claims, "nbf");
        if (notBefore != null && now.plus(clockSkew).isBefore(notBefore)) {
            throw new SecurityException("JWS is not valid before " + notBefore);
        }
    }

    /**
     * Read a NumericDate claim.
     *
     * @param claims the claims of the token
     * @param name   name of the claim to read
     * @return the claim as an instant, or null if it is absent
     * @throws SecurityException if the claim is present but not a number
     */
    @Nullable
    protected Instant readTimeClaim(@Nonnull final Map<String, Object> claims, @Nonnull final String name)
            throws SecurityException {
        final Object value = claims.get(name);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Number)) {
            throw new SecurityException("JWS claim '" + name + "' is not a number");
        }
        return Instant.ofEpochSecond(((Number) value).longValue());
    }

    /**
     * Base64url decode one part of a compact serialization.
     *
     * @param part the encoded part
     * @param what what the part is, for the error message
     * @return the decoded bytes
     * @throws SecurityException if the part is not valid base64url
     */
    @Nonnull
    protected byte[] decodeBase64Url(@Nonnull final String part, @Nonnull final String what) throws SecurityException {
        try {
            return Base64.getUrlDecoder().decode(part);
        } catch (final IllegalArgumentException e) {
            throw new SecurityException("JWS " + what + " is not valid base64url", e);
        }
    }

    /**
     * Base64url decode one part of a compact serialization and parse it as a JSON
     * object.
     *
     * @param part the encoded part
     * @param what what the part is, for the error message
     * @return the parsed object
     * @throws SecurityException if the part is not valid base64url or does not hold
     *                           a JSON object
     */
    @Nonnull
    protected Map<String, Object> decodeJson(@Nonnull final String part, @Nonnull final String what)
            throws SecurityException {
        try {
            final Map<String, Object> parsed = objectMapper.readValue(decodeBase64Url(part, what),
                    new TypeReference<Map<String, Object>>() {
                    });
            if (parsed == null) {
                throw new SecurityException("JWS " + what + " is not a JSON object");
            }
            return parsed;
        } catch (final IOException e) {
            throw new SecurityException("JWS " + what + " is not a JSON object", e);
        }
    }
}
