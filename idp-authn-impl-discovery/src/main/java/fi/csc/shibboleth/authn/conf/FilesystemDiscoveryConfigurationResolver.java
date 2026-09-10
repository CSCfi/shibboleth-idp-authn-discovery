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
import java.io.IOException;
import java.time.Instant;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * A {@link DiscoveryConfigurationResolver} that reads the configuration from a
 * local file, re-reading it when the file's modification time changes.
 */
public class FilesystemDiscoveryConfigurationResolver extends AbstractReloadingDiscoveryConfigurationResolver {

    /** The configuration file. */
    @Nonnull
    private final File configurationFile;

    /**
     * Constructor.
     *
     * @param file the configuration file
     */
    public FilesystemDiscoveryConfigurationResolver(@Nonnull @ParameterName(name = "file") final File file) {
        this(null, file);
    }

    /**
     * Constructor.
     *
     * @param backgroundTaskTimer timer used to schedule background refresh tasks,
     *                            or null to create a private one
     * @param file                the configuration file
     */
    public FilesystemDiscoveryConfigurationResolver(
            @Nullable @ParameterName(name = "backgroundTaskTimer") final Timer backgroundTaskTimer,
            @Nonnull @ParameterName(name = "file") final File file) {
        super(backgroundTaskTimer);

        configurationFile = Constraint.isNotNull(file, "Discovery configuration file cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected String getConfigurationIdentifier() {
        return configurationFile.getAbsolutePath();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    protected byte[] fetchConfiguration() throws ResolverException {
        validateConfigurationFile(configurationFile);

        final Instant fileUpdateTime = Instant.ofEpochMilli(configurationFile.lastModified());
        final Instant lastUpdate = getLastUpdate();
        if (lastUpdate != null && !fileUpdateTime.isAfter(lastUpdate)) {
            return null;
        }

        try {
            return inputStreamToByteArray(new FileInputStream(configurationFile));
        } catch (final IOException e) {
            throw new ResolverException(
                    "Unable to read discovery configuration file " + configurationFile.getAbsolutePath(), e);
        }
    }

    /**
     * Validate that the file exists, is a file and is readable.
     *
     * @param file the file to evaluate
     * @throws ResolverException if it is not usable
     */
    protected void validateConfigurationFile(@Nonnull final File file) throws ResolverException {
        if (!file.exists()) {
            throw new ResolverException("Discovery configuration file '" + file.getAbsolutePath() + "' does not exist");
        }
        if (!file.isFile()) {
            throw new ResolverException("Discovery configuration file '" + file.getAbsolutePath() + "' is not a file");
        }
        if (!file.canRead()) {
            throw new ResolverException(
                    "Discovery configuration file '" + file.getAbsolutePath() + "' is not readable");
        }
    }
}
