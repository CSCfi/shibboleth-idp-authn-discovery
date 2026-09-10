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
import java.time.Instant;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.service.ServiceException;
import net.shibboleth.shared.service.ServiceableComponent;

/**
 * Unit tests for {@link FilesystemDiscoveryConfigurationResolver}.
 */
public class FilesystemDiscoveryConfigurationResolverTest {

    private static final String ONE_FLOW =
            "{ \"default\": { \"authn/test1\": [ { \"acr\": \"urn:one\" } ] } }";

    private static final String TWO_FLOWS = "{ \"default\": { \"authn/test1\": [ { \"acr\": \"urn:one\" } ], "
            + "\"authn/test2\": [ { \"acr\": \"urn:two\" } ] } }";

    private Path file;

    /** The resolver under test. */
    private FilesystemDiscoveryConfigurationResolver resolver;

    @BeforeMethod
    public void setUp() throws Exception {
        file = Files.createTempFile("discovery-authorities", ".json");
    }

    @AfterMethod
    public void tearDown() throws Exception {
        if (resolver != null) {
            resolver.destroy();
            resolver = null;
        }
        Files.deleteIfExists(file);
    }

    private void write(final String content) throws Exception {
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
    }

    private void buildResolver() throws ComponentInitializationException {
        resolver = new FilesystemDiscoveryConfigurationResolver(file.toFile());
        resolver.setId("test");
        resolver.setRefreshInterval(Duration.ZERO);
        resolver.initialize();
    }

    @Test
    public void testInitialLoad() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        Assert.assertNotNull(resolver.resolve());
        Assert.assertTrue(resolver.resolve().getFlowMap().get("default").getAuthorityMap().containsKey("authn/test1"));
        Assert.assertNotNull(resolver.getLastUpdate());
        Assert.assertNotNull(resolver.getLastSuccessfulRefresh());
        Assert.assertNull(resolver.getLastFailureCause());
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testMissingFileIsFatalOnFirstLoad() throws Exception {
        Files.delete(file);
        buildResolver();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testMalformedJsonIsFatalOnFirstLoad() throws Exception {
        write("{ this is not json");
        buildResolver();
    }

    @Test
    public void testUnchangedFileIsNotReloaded() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        final DiscoveryConfiguration first = resolver.resolve();
        final Instant firstUpdate = resolver.getLastUpdate();

        resolver.refresh();

        Assert.assertSame(resolver.resolve(), first);
        Assert.assertEquals(resolver.getLastUpdate(), firstUpdate);
    }

    @Test
    public void testChangedFileIsReloaded() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        final DiscoveryConfiguration first = resolver.resolve();
        Assert.assertFalse(first.getFlowMap().get("default").getAuthorityMap().containsKey("authn/test2"));

        write(TWO_FLOWS);
        // Modification time must be later than the last update.
        Assert.assertTrue(file.toFile().setLastModified(System.currentTimeMillis() + 10000));

        resolver.refresh();

        Assert.assertNotSame(resolver.resolve(), first);
        Assert.assertTrue(resolver.resolve().getFlowMap().get("default").getAuthorityMap()
                .containsKey("authn/test2"));
    }

    @Test
    public void testBadEditRetainsEffectiveConfiguration() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        final DiscoveryConfiguration good = resolver.resolve();

        write("{ broken");
        Assert.assertTrue(file.toFile().setLastModified(System.currentTimeMillis() + 10000));

        try {
            resolver.refresh();
            Assert.fail("Refresh of a malformed configuration should have thrown");
        } catch (final ResolverException e) {
            // Expected.
        }

        Assert.assertSame(resolver.resolve(), good);
        Assert.assertNotNull(resolver.getLastFailureCause());
    }

    @Test
    public void testReloadPicksUpChanges() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        final DiscoveryConfiguration first = resolver.resolve();

        write(TWO_FLOWS);
        Assert.assertTrue(file.toFile().setLastModified(System.currentTimeMillis() + 10000));

        resolver.reload();

        Assert.assertNotSame(resolver.resolve(), first);
        Assert.assertTrue(resolver.resolve().getFlowMap().get("default").getAuthorityMap()
                .containsKey("authn/test2"));
    }

    @Test
    public void testReloadReportsFailureAsServiceException() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        final DiscoveryConfiguration good = resolver.resolve();

        write("{ broken");
        Assert.assertTrue(file.toFile().setLastModified(System.currentTimeMillis() + 10000));

        try {
            resolver.reload();
            Assert.fail("Reload of a malformed configuration should have thrown");
        } catch (final ServiceException e) {
            Assert.assertNotNull(e.getCause());
        }

        Assert.assertSame(resolver.resolve(), good);
    }

    @Test
    public void testServiceMetadataMirrorsRefreshMetadata() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        Assert.assertEquals(resolver.getLastReloadAttemptInstant(), resolver.getLastRefresh());
        Assert.assertEquals(resolver.getLastSuccessfulReloadInstant(), resolver.getLastSuccessfulRefresh());
        Assert.assertNull(resolver.getReloadFailureCause());

        write("{ broken");
        Assert.assertTrue(file.toFile().setLastModified(System.currentTimeMillis() + 10000));
        try {
            resolver.reload();
        } catch (final ServiceException e) {
            // Expected.
        }

        Assert.assertNotNull(resolver.getReloadFailureCause());
        Assert.assertEquals(resolver.getReloadFailureCause(), resolver.getLastFailureCause());
    }

    @Test
    public void testServiceableComponentGivesTheEffectiveConfiguration() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        final DiscoveryConfiguration effective = resolver.resolve();
        try (ServiceableComponent<DiscoveryConfiguration> component = resolver.getServiceableComponent()) {
            Assert.assertSame(component.getComponent(), effective);
        }

        Assert.assertSame(resolver.resolve(), effective);
    }

    @Test
    public void testDeletedFileRetainsEffectiveConfiguration() throws Exception {
        write(ONE_FLOW);
        buildResolver();

        final DiscoveryConfiguration good = resolver.resolve();
        Files.delete(file);

        try {
            resolver.refresh();
            Assert.fail("Refresh of a missing configuration should have thrown");
        } catch (final ResolverException e) {
            // Expected.
        }

        Assert.assertSame(resolver.resolve(), good);
    }
}
