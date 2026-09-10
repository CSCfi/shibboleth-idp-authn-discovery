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

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.component.ComponentInitializationException;

/**
 * Unit tests for {@link SignedJWTDiscoveryConfigurationResolver}. The URL points at a port nothing listens on, so
 * every test loads its token from the backup file.
 */
public class SignedJWTDiscoveryConfigurationResolverTest {

    private static final String UNREACHABLE_URL = "http://127.0.0.1:1/discovery-authorities.jwt";

    private static final Map<String, Object> CONFIGURATION =
            Map.of("default", Map.of("authn/test1", List.of(Map.of("acr", "urn:one"))));

    private Path backupFile;

    private CloseableHttpClient httpClient;

    private JWTTestSupport.KeyPairHolder signer;

    private JWTTestSupport.KeyPairHolder stranger;

    private SignedJWTDiscoveryConfigurationResolver resolver;

    @BeforeMethod
    public void setUp() throws Exception {
        backupFile = Files.createTempFile("discovery-authorities-backup", ".jwt");
        Files.delete(backupFile);
        httpClient = HttpClients.createDefault();
        signer = JWTTestSupport.rsaKeyPair();
        stranger = JWTTestSupport.rsaKeyPair();
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (resolver != null) {
            resolver.destroy();
            resolver = null;
        }
        if (httpClient != null) {
            httpClient.close();
            httpClient = null;
        }
        Files.deleteIfExists(backupFile);
    }

    private void buildResolver(final JWTTestSupport.KeyPairHolder trusted) throws Exception {
        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(List.<Credential>of(new BasicCredential(trusted.getPublicKey())));

        resolver = new SignedJWTDiscoveryConfigurationResolver(httpClient, UNREACHABLE_URL, backupFile.toString());
        resolver.setId("test");
        resolver.setRefreshInterval(Duration.ZERO);
        resolver.setVerifier(verifier);
        resolver.initialize();
    }

    @Test
    public void testLoadsSignedTokenFromBackupFile() throws Exception {
        Files.write(backupFile, JWTTestSupport.sign(signer, "RS256", CONFIGURATION));

        buildResolver(signer);

        Assert.assertTrue(resolver.resolve().getFlowMap().get("default").getAuthorityMap()
                .containsKey("authn/test1"));
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testTokenSignedByStrangerIsRejected() throws Exception {
        Files.write(backupFile, JWTTestSupport.sign(stranger, "RS256", CONFIGURATION));

        buildResolver(signer);
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testTamperedTokenIsRejected() throws Exception {
        final byte[] token = JWTTestSupport.sign(signer, "RS256", CONFIGURATION);
        // Change a character in the middle of the payload.
        final String compact = new String(token, "US-ASCII");
        final int payloadStart = compact.indexOf('.') + 1;
        final int payloadEnd = compact.lastIndexOf('.');
        final int victim = (payloadStart + payloadEnd) / 2;
        final char original = compact.charAt(victim);
        final String tampered = compact.substring(0, victim) + (original == 'a' ? 'b' : 'a')
                + compact.substring(victim + 1);
        Assert.assertNotEquals(tampered, compact);
        Files.write(backupFile, tampered.getBytes("US-ASCII"));

        buildResolver(signer);
    }

    private void buildResolverExpectingClaim(final String claim) throws Exception {
        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(List.<Credential>of(new BasicCredential(signer.getPublicKey())));

        resolver = new SignedJWTDiscoveryConfigurationResolver(httpClient, UNREACHABLE_URL, backupFile.toString());
        resolver.setId("test");
        resolver.setRefreshInterval(Duration.ZERO);
        resolver.setVerifier(verifier);
        resolver.setConfigurationClaim(claim);
        resolver.initialize();
    }

    @Test
    public void testConfigurationNestedInAClaim() throws Exception {
        Files.write(backupFile, JWTTestSupport.sign(signer, "RS256",
                Map.of("iss", "https://config.example.com", "discovery", CONFIGURATION)));

        buildResolverExpectingClaim("discovery");

        Assert.assertTrue(resolver.resolve().getFlowMap().get("default").getAuthorityMap()
                .containsKey("authn/test1"));
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testMissingConfigurationClaimIsRejected() throws Exception {
        Files.write(backupFile, JWTTestSupport.sign(signer, "RS256", Map.of("somethingElse", CONFIGURATION)));

        buildResolverExpectingClaim("discovery");
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testMissingVerifierIsFatal() throws Exception {
        Files.write(backupFile, JWTTestSupport.sign(signer, "RS256", CONFIGURATION));

        resolver = new SignedJWTDiscoveryConfigurationResolver(httpClient, UNREACHABLE_URL, backupFile.toString());
        resolver.setId("test");
        resolver.setRefreshInterval(Duration.ZERO);
        resolver.initialize();
    }
}
