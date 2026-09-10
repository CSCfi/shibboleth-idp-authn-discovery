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

import java.io.File;
import java.nio.file.Files;
import java.util.List;

import org.opensaml.security.credential.Credential;
import org.opensaml.spring.credential.BasicResourceCredentialFactoryBean;
import org.opensaml.spring.credential.BasicX509CredentialFactoryBean;
import org.springframework.core.io.FileSystemResource;
import org.testng.Assert;
import org.testng.annotations.Test;

import net.shibboleth.shared.spring.resource.ResourceHelper;

/**
 * Unit tests for each documented way of supplying a verification key, against a signed token fixture. The OP
 * plugin's {@code shibboleth.JWKCredential} is not covered, as its factory bean is in an OIDC artifact this module
 * does not depend on.
 */
public class CredentialWiringTest {

    private static final String JWT = "./src/test/resources/example-discovery-authorities.jwt";

    private static final String CERTIFICATE = "./src/test/resources/example-discovery-signing.crt";

    private static final String PUBLIC_KEY = "./src/test/resources/example-discovery-signing.pub";

    private void assertVerifiesToken(final List<Credential> credentials) throws Exception {
        final SignedJWTVerifier verifier = new SignedJWTVerifier();
        verifier.setCredentials(credentials);
        verifier.setSignatureAlgorithms(List.of("RS256"));
        verifier.initialize();

        final DiscoveryConfiguration configuration = DiscoveryConfiguration
                .parse(verifier.verify(Files.readAllBytes(new File(JWT).toPath())));

        Assert.assertEquals(configuration.getFlowMap().size(), 36);
        Assert.assertTrue(configuration.getFlowMap().containsKey("default"));
    }

    @Test
    public void testCertificateFileWiring() throws Exception {
        final BasicX509CredentialFactoryBean factory = new BasicX509CredentialFactoryBean();
        factory.setCertificateResource(ResourceHelper.of(new FileSystemResource(CERTIFICATE)));
        factory.afterPropertiesSet();

        final Credential credential = factory.getObject();
        Assert.assertNotNull(credential);
        Assert.assertNotNull(credential.getPublicKey());

        assertVerifiesToken(List.of(credential));
    }

    @Test
    public void testPublicKeyFileWiring() throws Exception {
        final BasicResourceCredentialFactoryBean factory = new BasicResourceCredentialFactoryBean();
        factory.setPublicKeyInfo(ResourceHelper.of(new FileSystemResource(PUBLIC_KEY)));
        factory.afterPropertiesSet();

        final Credential credential = factory.getObject();
        Assert.assertNotNull(credential);
        Assert.assertNotNull(credential.getPublicKey());

        assertVerifiesToken(List.of(credential));
    }

    @Test
    public void testBothRoutesYieldTheSameKey() throws Exception {
        final BasicX509CredentialFactoryBean certificate = new BasicX509CredentialFactoryBean();
        certificate.setCertificateResource(ResourceHelper.of(new FileSystemResource(CERTIFICATE)));
        certificate.afterPropertiesSet();

        final BasicResourceCredentialFactoryBean publicKey = new BasicResourceCredentialFactoryBean();
        publicKey.setPublicKeyInfo(ResourceHelper.of(new FileSystemResource(PUBLIC_KEY)));
        publicKey.afterPropertiesSet();

        Assert.assertEquals(certificate.getObject().getPublicKey().getEncoded(),
                publicKey.getObject().getPublicKey().getEncoded());
    }
}
