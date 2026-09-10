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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * Unit tests for {@link FileBackedHTTPDiscoveryConfigurationResolver}. The URL points at a port nothing listens on,
 * exercising the fallback to the backup file.
 */
public class FileBackedHTTPDiscoveryConfigurationResolverTest {

    private static final String UNREACHABLE_URL = "http://127.0.0.1:1/discovery-authorities.json";

    private static final String CONFIGURATION =
            "{ \"default\": { \"authn/test1\": [ { \"acr\": \"urn:one\" } ] } }";

    private Path backupFile;

    private CloseableHttpClient httpClient;

    private FileBackedHTTPDiscoveryConfigurationResolver resolver;

    @BeforeMethod
    public void setUp() throws Exception {
        backupFile = Files.createTempFile("discovery-authorities-backup", ".json");
        Files.delete(backupFile);
        httpClient = HttpClients.createDefault();
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

    private void buildResolver() throws ComponentInitializationException, ResolverException {
        resolver = new FileBackedHTTPDiscoveryConfigurationResolver(httpClient, UNREACHABLE_URL,
                backupFile.toString());
        resolver.setId("test");
        resolver.setRefreshInterval(Duration.ZERO);
        resolver.initialize();
    }

    @Test
    public void testFallsBackToBackupFile() throws Exception {
        Files.write(backupFile, CONFIGURATION.getBytes(StandardCharsets.UTF_8));

        buildResolver();

        Assert.assertNotNull(resolver.resolve());
        Assert.assertTrue(resolver.resolve().getFlowMap().get("default").getAuthorityMap().containsKey("authn/test1"));
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testNoRemoteAndNoBackupIsFatalOnFirstLoad() throws Exception {
        buildResolver();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testMalformedBackupFileIsFatalOnFirstLoad() throws Exception {
        Files.write(backupFile, "{ broken".getBytes(StandardCharsets.UTF_8));

        buildResolver();
    }

    @Test
    public void testUnreachableRemoteRetainsEffectiveConfiguration() throws Exception {
        Files.write(backupFile, CONFIGURATION.getBytes(StandardCharsets.UTF_8));
        buildResolver();

        final DiscoveryConfiguration loaded = resolver.resolve();

        // A configuration is in effect by now, so the cycle fails rather than re-reading the backup file.
        try {
            resolver.refresh();
            Assert.fail("Refresh against an unreachable remote should have thrown");
        } catch (final ResolverException e) {
            // Expected.
        }

        Assert.assertSame(resolver.resolve(), loaded);
        Assert.assertNotNull(resolver.getLastFailureCause());
    }

    @Test(expectedExceptions = ResolverException.class)
    public void testInvalidUrlIsRejected() throws Exception {
        new FileBackedHTTPDiscoveryConfigurationResolver(httpClient, "not a url", backupFile.toString());
    }
}
