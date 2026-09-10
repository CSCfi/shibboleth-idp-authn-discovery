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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * A {@link DiscoveryConfigurationResolver} that fetches the configuration over
 * HTTP with a conditional GET and keeps a copy of every parsed response in a
 * local backup file. The backup is read only during the initial load, when
 * there is nothing in effect to fall back on.
 *
 * <p>
 * Modelled on
 * {@code org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver}.
 * </p>
 */
public class FileBackedHTTPDiscoveryConfigurationResolver extends AbstractReloadingDiscoveryConfigurationResolver {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(FileBackedHTTPDiscoveryConfigurationResolver.class);

    /** HTTP client used to fetch the configuration. */
    @Nonnull
    private final HttpClient httpClient;

    /** URL the configuration is fetched from. */
    @Nonnull
    private final URI configurationURI;

    /** File holding the backup copy of the configuration. */
    @Nonnull
    private final File backupFile;

    /** The ETag provided with the currently cached configuration. */
    @Nullable
    private String cachedETag;

    /** The Last-Modified value provided with the currently cached configuration. */
    @Nullable
    private String cachedLastModified;

    /**
     * Whether the bytes returned by the current fetch came from the backup file.
     */
    private boolean fetchedFromBackupFile;

    /**
     * Constructor.
     *
     * @param client         HTTP client used to fetch the configuration
     * @param url            URL the configuration is fetched from
     * @param backupFilePath path of the file holding the backup copy of the
     *                       configuration
     * @throws ResolverException if the URL is not valid
     */
    public FileBackedHTTPDiscoveryConfigurationResolver(
            @Nonnull @ParameterName(name = "client") final HttpClient client,
            @Nonnull @ParameterName(name = "url") final String url,
            @Nonnull @ParameterName(name = "backupFilePath") final String backupFilePath) throws ResolverException {
        this(null, client, url, backupFilePath);
    }

    /**
     * Constructor.
     *
     * @param backgroundTaskTimer timer used to schedule background refresh tasks,
     *                            or null to create a private one
     * @param client              HTTP client used to fetch the configuration
     * @param url                 URL the configuration is fetched from
     * @param backupFilePath      path of the file holding the backup copy of the
     *                            configuration
     * @throws ResolverException if the URL is not valid
     */
    public FileBackedHTTPDiscoveryConfigurationResolver(
            @Nullable @ParameterName(name = "backgroundTaskTimer") final Timer backgroundTaskTimer,
            @Nonnull @ParameterName(name = "client") final HttpClient client,
            @Nonnull @ParameterName(name = "url") final String url,
            @Nonnull @ParameterName(name = "backupFilePath") final String backupFilePath) throws ResolverException {
        super(backgroundTaskTimer);

        httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");
        Constraint.isNotNull(backupFilePath, "Backup file path cannot be null");
        backupFile = new File(backupFilePath);
        try {
            configurationURI = new URI(Constraint.isNotNull(url, "Configuration URL cannot be null"));
        } catch (final URISyntaxException e) {
            throw new ResolverException("Illegal discovery configuration URL syntax", e);
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected String getConfigurationIdentifier() {
        return configurationURI.toString();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    protected byte[] fetchConfiguration() throws ResolverException {
        fetchedFromBackupFile = false;
        try {
            return fetchFromRemote();
        } catch (final ResolverException e) {
            return recoverFromFailedFetch(e);
        }
    }

    /**
     * Fetch the configuration from the remote source.
     *
     * @return the fetched configuration, or null on a 304
     * @throws ResolverException if the configuration cannot be fetched
     */
    @Nullable
    protected byte[] fetchFromRemote() throws ResolverException {
        final HttpGet httpGet = buildHttpGet();

        log.debug("{} Fetching discovery configuration from '{}'", getLogPrefix(), configurationURI);
        try (final ClassicHttpResponse response = httpClient.executeOpen(null, httpGet, HttpClientContext.create())) {
            final int statusCode = response.getCode();
            if (statusCode == HttpStatus.SC_NOT_MODIFIED) {
                return null;
            }
            if (statusCode != HttpStatus.SC_OK) {
                throw new ResolverException("Non-ok status code " + statusCode
                        + " returned from discovery configuration source " + configurationURI);
            }
            final byte[] bytes = readEntity(response);
            recordConditionalHeaders(response);
            return bytes;
        } catch (final IOException e) {
            throw new ResolverException("Error retrieving discovery configuration from " + configurationURI, e);
        }
    }

    /**
     * Build the request, replaying any cached {@code ETag} and
     * {@code Last-Modified}.
     *
     * @return the request to issue
     */
    @Nonnull
    protected HttpGet buildHttpGet() {
        final HttpGet httpGet = new HttpGet(configurationURI);
        if (cachedETag != null) {
            httpGet.setHeader("If-None-Match", cachedETag);
        }
        if (cachedLastModified != null) {
            httpGet.setHeader("If-Modified-Since", cachedLastModified);
        }
        return httpGet;
    }

    /**
     * Read the body of a response.
     *
     * @param response the response to read
     * @return the body of the response
     * @throws ResolverException if the body cannot be read
     */
    @Nonnull
    protected byte[] readEntity(@Nonnull final ClassicHttpResponse response) throws ResolverException {
        try (final HttpEntity entity = response.getEntity()) {
            if (entity == null) {
                throw new ResolverException(
                        "No content returned from discovery configuration source " + configurationURI);
            }
            return inputStreamToByteArray(entity.getContent());
        } catch (final IOException e) {
            throw new ResolverException("Unable to read discovery configuration response", e);
        }
    }

    /**
     * Record the ETag and Last-Modified headers for the next fetch.
     *
     * @param response the response to read the headers from
     */
    protected void recordConditionalHeaders(@Nonnull final ClassicHttpResponse response) {
        final Header etag = response.getFirstHeader("ETag");
        cachedETag = etag != null ? etag.getValue() : null;

        final Header lastModified = response.getFirstHeader("Last-Modified");
        cachedLastModified = lastModified != null ? lastModified.getValue() : null;
    }

    /**
     * Fall back to the backup file, but only while nothing is in effect yet. Once a
     * configuration is in effect it is at least as fresh as the backup, so the
     * failure is propagated instead.
     *
     * @param cause the failure to recover from
     * @return the contents of the backup file
     * @throws ResolverException if a configuration is already in effect, or there
     *                           is no usable backup file
     */
    @Nonnull
    protected byte[] recoverFromFailedFetch(@Nonnull final ResolverException cause) throws ResolverException {
        if (getLastUpdate() != null) {
            log.debug("{} Could not read discovery configuration from '{}', the one already in effect is retained",
                    getLogPrefix(), configurationURI);
            throw cause;
        }

        if (!backupFile.exists() || !backupFile.canRead()) {
            log.error("{} Could not read discovery configuration from '{}' and backup file '{}' is not available",
                    getLogPrefix(), configurationURI, backupFile.getAbsolutePath());
            throw cause;
        }

        log.warn("{} Could not read discovery configuration from '{}', falling back to backup file '{}'",
                getLogPrefix(), configurationURI, backupFile.getAbsolutePath(), cause);
        try {
            final byte[] bytes = inputStreamToByteArray(new FileInputStream(backupFile));
            fetchedFromBackupFile = true;
            return bytes;
        } catch (final IOException e) {
            throw new ResolverException(
                    "Unable to read discovery configuration backup file " + backupFile.getAbsolutePath(), e);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void onConfigurationUpdated(@Nonnull final byte[] bytes) {
        if (fetchedFromBackupFile) {
            return;
        }
        writeBackupFile(bytes);
    }

    /**
     * Write a parsed configuration to the backup file, staged so a partial write
     * cannot replace a good backup. Failures are logged rather than propagated.
     *
     * @param bytes the configuration to write
     */
    protected void writeBackupFile(@Nonnull final byte[] bytes) {
        final File staging = new File(backupFile.getAbsolutePath() + ".staging");
        try {
            try (final FileOutputStream out = new FileOutputStream(staging)) {
                out.write(bytes);
                out.flush();
            }
            Files.move(staging.toPath(), backupFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            log.debug("{} Wrote discovery configuration backup file '{}'", getLogPrefix(),
                    backupFile.getAbsolutePath());
        } catch (final IOException e) {
            log.warn("{} Unable to write discovery configuration backup file '{}'", getLogPrefix(),
                    backupFile.getAbsolutePath(), e);
        } finally {
            if (staging.exists() && !staging.delete()) {
                log.debug("{} Could not remove staging file '{}'", getLogPrefix(), staging.getAbsolutePath());
            }
        }
    }
}
