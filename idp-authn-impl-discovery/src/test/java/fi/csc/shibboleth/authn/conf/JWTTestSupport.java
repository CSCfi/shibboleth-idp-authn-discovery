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

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Builds signed and unsigned JWTs for the tests, using only the JDK.
 */
public final class JWTTestSupport {

    /** JSON mapper. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** JOSE algorithm to the JCA algorithm used to sign with it. */
    private static final Map<String, String> JCA_ALGORITHMS = Map.of(
            "RS256", "SHA256withRSA",
            "RS384", "SHA384withRSA",
            "RS512", "SHA512withRSA",
            "ES256", "SHA256withECDSAinP1363Format",
            "ES384", "SHA384withECDSAinP1363Format",
            "ES512", "SHA512withECDSAinP1363Format");

    /** Constructor. */
    private JWTTestSupport() {
    }

    /** A generated key pair. */
    public static final class KeyPairHolder {

        /** The public key. */
        private final PublicKey publicKey;

        /** The private key. */
        private final PrivateKey privateKey;

        /**
         * Constructor.
         *
         * @param pair the generated pair
         */
        KeyPairHolder(final KeyPair pair) {
            publicKey = pair.getPublic();
            privateKey = pair.getPrivate();
        }

        /**
         * Get the public key.
         *
         * @return the public key
         */
        public PublicKey getPublicKey() {
            return publicKey;
        }

        /**
         * Get the private key.
         *
         * @return the private key
         */
        public PrivateKey getPrivateKey() {
            return privateKey;
        }
    }

    /**
     * Generate an RSA key pair.
     *
     * @return the generated pair
     * @throws Exception if generation fails
     */
    public static KeyPairHolder rsaKeyPair() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return new KeyPairHolder(generator.generateKeyPair());
    }

    /**
     * Generate a P-256 EC key pair.
     *
     * @return the generated pair
     * @throws Exception if generation fails
     */
    public static KeyPairHolder ecKeyPair() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return new KeyPairHolder(generator.generateKeyPair());
    }

    /**
     * Build a signed JWT.
     *
     * @param signer    the key pair to sign with
     * @param algorithm the JOSE algorithm
     * @param claims    the payload claims
     * @return the token in compact serialization
     * @throws Exception if signing fails
     */
    public static byte[] sign(final KeyPairHolder signer, final String algorithm, final Map<String, Object> claims)
            throws Exception {
        return sign(signer, algorithm, claims, Map.of());
    }

    /**
     * Build a signed JWT with extra header members.
     *
     * @param signer      the key pair to sign with
     * @param algorithm   the JOSE algorithm
     * @param claims      the payload claims
     * @param extraHeader header members to add alongside alg and typ
     * @return the token in compact serialization
     * @throws Exception if signing fails
     */
    public static byte[] sign(final KeyPairHolder signer, final String algorithm, final Map<String, Object> claims,
            final Map<String, Object> extraHeader) throws Exception {

        final Map<String, Object> header = new HashMap<>(extraHeader);
        header.put("alg", algorithm);
        header.put("typ", "JWT");

        final String signingInput = encode(MAPPER.writeValueAsBytes(header)) + "."
                + encode(MAPPER.writeValueAsBytes(claims));

        final Signature signature = Signature.getInstance(JCA_ALGORITHMS.get(algorithm));
        signature.initSign(signer.getPrivateKey());
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));

        return (signingInput + "." + encode(signature.sign())).getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Build a token with an empty signature part.
     *
     * @param algorithm the JOSE algorithm to claim in the header
     * @param claims    the payload claims
     * @return the token in compact serialization
     * @throws Exception if the token cannot be built
     */
    public static byte[] unsigned(final String algorithm, final Map<String, Object> claims) throws Exception {
        final Map<String, Object> header = Map.of("alg", algorithm, "typ", "JWT");
        final String token = encode(MAPPER.writeValueAsBytes(header)) + "."
                + encode(MAPPER.writeValueAsBytes(claims)) + ".";
        return token.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Base64url encode without padding.
     *
     * @param bytes what to encode
     * @return the encoded value
     */
    private static String encode(final byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
