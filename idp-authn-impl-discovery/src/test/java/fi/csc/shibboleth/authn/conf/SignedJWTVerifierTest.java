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

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import net.shibboleth.shared.component.ComponentInitializationException;

/**
 * Unit tests for {@link SignedJWTVerifier}.
 */
public class SignedJWTVerifierTest {

    private JWTTestSupport.KeyPairHolder rsa;

    private JWTTestSupport.KeyPairHolder otherRsa;

    private JWTTestSupport.KeyPairHolder ec;

    @BeforeClass
    public void generateKeys() throws Exception {
        rsa = JWTTestSupport.rsaKeyPair();
        otherRsa = JWTTestSupport.rsaKeyPair();
        ec = JWTTestSupport.ecKeyPair();
    }

    private SignedJWTVerifier verifierFor(final JWTTestSupport.KeyPairHolder... holders)
            throws ComponentInitializationException {
        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(List.of(holders).stream()
                .map(h -> (Credential) new BasicCredential(h.getPublicKey()))
                .toList());
        verifier.initialize();
        return verifier;
    }

    @Test
    public void testRs256RoundTrip() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256", Map.of("discovery", Map.of("k", "v")));

        final Map<String, Object> claims = verifierFor(rsa).verify(token);

        Assert.assertEquals(claims.get("discovery"), Map.of("k", "v"));
    }

    @Test
    public void testEs256RoundTrip() throws Exception {
        final byte[] token = JWTTestSupport.sign(ec, "ES256", Map.of("discovery", Map.of("k", "v")));

        final Map<String, Object> claims = verifierFor(ec).verify(token);

        Assert.assertEquals(claims.get("discovery"), Map.of("k", "v"));
    }

    @Test
    public void testKeyRolloverTriesEveryCredential() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256", Map.of("k", "v"));

        // The signing key is listed second, and an EC key that cannot apply at all is in the mix.
        final Map<String, Object> claims = verifierFor(otherRsa, rsa, ec).verify(token);

        Assert.assertEquals(claims.get("k"), "v");
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testWrongKeyIsRejected() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256", Map.of("k", "v"));

        verifierFor(otherRsa).verify(token);
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testNoCredentialOfMatchingKeyTypeIsRejected() throws Exception {
        final byte[] token = JWTTestSupport.sign(ec, "ES256", Map.of("k", "v"));

        verifierFor(rsa).verify(token);
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testAlgNoneIsRejected() throws Exception {
        verifierFor(rsa).verify(JWTTestSupport.unsigned("none", Map.of("k", "v")));
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testHmacAlgIsRejected() throws Exception {
        verifierFor(rsa).verify(JWTTestSupport.unsigned("HS256", Map.of("k", "v")));
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testAlgorithmOutsideAllowListIsRejected() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS512", Map.of("k", "v"));

        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(List.of(new BasicCredential(rsa.getPublicKey())));
        verifier.setSignatureAlgorithms(List.of("RS256"));
        verifier.initialize();

        verifier.verify(token);
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testCritHeaderIsRejected() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256", Map.of("k", "v"), Map.of("crit", List.of("x")));

        verifierFor(rsa).verify(token);
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testMalformedTokenIsRejected() throws Exception {
        verifierFor(rsa).verify("not.ajwt".getBytes("UTF-8"));
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testExpiredTokenIsRejected() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256",
                Map.of("k", "v", "exp", Instant.now().minusSeconds(3600).getEpochSecond()));

        verifierFor(rsa).verify(token);
    }

    @Test
    public void testExpiryWithinClockSkewIsAccepted() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256",
                Map.of("k", "v", "exp", Instant.now().minusSeconds(10).getEpochSecond()));

        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(List.of(new BasicCredential(rsa.getPublicKey())));
        verifier.setClockSkew(Duration.ofMinutes(5));
        verifier.initialize();

        Assert.assertEquals(verifier.verify(token).get("k"), "v");
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testNotYetValidTokenIsRejected() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256",
                Map.of("k", "v", "nbf", Instant.now().plusSeconds(3600).getEpochSecond()));

        verifierFor(rsa).verify(token);
    }

    @Test(expectedExceptions = SecurityException.class)
    public void testMissingExpirationIsRejectedWhenRequired() throws Exception {
        final byte[] token = JWTTestSupport.sign(rsa, "RS256", Map.of("k", "v"));

        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(List.of(new BasicCredential(rsa.getPublicKey())));
        verifier.setRequireExpiration(true);
        verifier.initialize();

        verifier.verify(token);
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testNoCredentialsIsFatal() throws Exception {
        new SignedJWTVerifier().initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testUnsupportedAlgorithmIsFatal() throws Exception {
        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(List.of(new BasicCredential(rsa.getPublicKey())));
        verifier.setSignatureAlgorithms(List.of("HS256"));
        verifier.initialize();
    }
}
