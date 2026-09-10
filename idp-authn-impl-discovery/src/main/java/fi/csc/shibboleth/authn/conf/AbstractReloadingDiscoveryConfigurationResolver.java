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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Timer;
import java.util.TimerTask;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.shared.annotation.constraint.NotEmpty;
import net.shibboleth.shared.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.service.ServiceException;
import net.shibboleth.shared.service.ServiceableComponent;

/**
 * Base class for {@link DiscoveryConfigurationResolver} implementations that
 * cache their configuration and refresh it on a fixed interval. The
 * configuration in effect is replaced only by one that was fetched and parsed
 * successfully; a failure during {@link #initialize()} is fatal, later ones are
 * not.
 *
 * <p>
 * Modelled on
 * {@code org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver}.
 * </p>
 */
public abstract class AbstractReloadingDiscoveryConfigurationResolver extends AbstractIdentifiableInitializableComponent
        implements DiscoveryConfigurationResolver {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractReloadingDiscoveryConfigurationResolver.class);

    /** Timer used to schedule background refresh tasks. */
    @Nonnull
    private final Timer taskTimer;

    /** Whether the task timer was created by this object rather than injected. */
    private final boolean createdOwnTaskTimer;

    /** Current task to refresh the configuration. */
    @Nullable
    private RefreshTask refreshTask;

    /**
     * Interval between refresh cycles. A non-positive value disables background
     * refresh.
     */
    @Nonnull
    private Duration refreshInterval;

    /** Interval after which a failed refresh cycle is retried. */
    @Nonnull
    private Duration failedRefreshInterval;

    /** The configuration currently in effect. */
    @Nullable
    private volatile DiscoveryConfiguration configuration;

    /** Time the last refresh cycle occurred. */
    @Nullable
    private Instant lastRefresh;

    /** Time the last successful refresh cycle occurred. */
    @Nullable
    private Instant lastSuccessfulRefresh;

    /** Time the configuration in effect was last replaced. */
    @Nullable
    private Instant lastUpdate;

    /** Reason the last refresh failed. */
    @Nullable
    private Throwable lastFailureCause;

    /** Cached log prefix. */
    @Nullable
    private String logPrefix;

    /**
     * Constructor.
     *
     * @param backgroundTaskTimer timer used to schedule background refresh tasks,
     *                            or null to create a private one
     */
    protected AbstractReloadingDiscoveryConfigurationResolver(@Nullable final Timer backgroundTaskTimer) {
        if (backgroundTaskTimer == null) {
            taskTimer = new Timer(true);
            createdOwnTaskTimer = true;
        } else {
            taskTimer = backgroundTaskTimer;
            createdOwnTaskTimer = false;
        }
        refreshInterval = Duration.ofHours(1);
        failedRefreshInterval = Duration.ofMinutes(5);
    }

    /**
     * Get the interval between refresh cycles.
     *
     * @return interval between refresh cycles
     */
    @Nonnull
    public Duration getRefreshInterval() {
        return refreshInterval;
    }

    /**
     * Set the interval between refresh cycles, defaults to one hour. Zero or
     * negative disables background refresh.
     *
     * @param interval interval between refresh cycles
     */
    public void setRefreshInterval(@Nonnull final Duration interval) {
        checkSetterPreconditions();

        refreshInterval = Constraint.isNotNull(interval, "Refresh interval cannot be null");
    }

    /**
     * Get the interval after which a failed refresh cycle is retried.
     *
     * @return interval after which a failed refresh cycle is retried
     */
    @Nonnull
    public Duration getFailedRefreshInterval() {
        return failedRefreshInterval;
    }

    /**
     * Set the interval after which a failed refresh cycle is retried, defaults to
     * five minutes.
     *
     * @param interval interval after which a failed refresh cycle is retried
     */
    public void setFailedRefreshInterval(@Nonnull final Duration interval) {
        checkSetterPreconditions();

        failedRefreshInterval = Constraint.isNotNull(interval, "Failed refresh interval cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    public DiscoveryConfiguration resolve() {
        // Lock-free: refresh() holds the monitor for the duration of a fetch.
        final DiscoveryConfiguration current = configuration;
        if (current == null) {
            throw new IllegalStateException(
                    getLogPrefix() + " No discovery configuration in effect, the resolver is not usable");
        }
        return current;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Instant getLastRefresh() {
        return lastRefresh;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Instant getLastSuccessfulRefresh() {
        return lastSuccessfulRefresh;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Instant getLastUpdate() {
        return lastUpdate;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Throwable getLastFailureCause() {
        return lastFailureCause;
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Instant getLastReloadAttemptInstant() {
        return getLastRefresh();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Instant getLastSuccessfulReloadInstant() {
        return getLastSuccessfulRefresh();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Throwable getReloadFailureCause() {
        return getLastFailureCause();
    }

    /** {@inheritDoc} */
    @Override
    public void reload() {
        try {
            refresh();
        } catch (final ResolverException e) {
            throw new ServiceException("Could not reload the discovery configuration", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * An immutable snapshot rather than a pinned component, so {@code close()} does
     * nothing.
     * </p>
     */
    @Override
    @Nonnull
    public ServiceableComponent<DiscoveryConfiguration> getServiceableComponent() {
        final DiscoveryConfiguration current = configuration;
        if (current == null) {
            throw new ServiceException(getLogPrefix() + " No discovery configuration in effect");
        }
        return new ServiceableComponent<>() {

            /** {@inheritDoc} */
            @Override
            @Nonnull
            public DiscoveryConfiguration getComponent() {
                return current;
            }

            /** {@inheritDoc} */
            @Override
            public void close() {
            }
        };
    }

    /** {@inheritDoc} */
    @Override
    public synchronized void refresh() throws ResolverException {
        if (isDestroyed()) {
            return;
        }
        // This cycle schedules its own task.
        if (refreshTask != null) {
            refreshTask.cancel();
            refreshTask = null;
        }

        final Instant now = Instant.now();
        Duration nextDelay = refreshInterval;
        try {
            final byte[] bytes = fetchConfiguration();
            if (bytes == null) {
                log.debug("{} Configuration from '{}' has not changed since last refresh", getLogPrefix(),
                        getConfigurationIdentifier());
            } else {
                final DiscoveryConfiguration newConfiguration = parseConfiguration(bytes);
                // Anything thrown before this point leaves the previous configuration in place.
                configuration = newConfiguration;
                lastUpdate = now;
                log.info("{} New discovery configuration loaded from '{}'", getLogPrefix(),
                        getConfigurationIdentifier());
                onConfigurationUpdated(bytes);
            }
            lastSuccessfulRefresh = now;
            lastFailureCause = null;
        } catch (final Exception e) {
            lastFailureCause = e;
            nextDelay = failedRefreshInterval;
            log.error("{} Error refreshing discovery configuration from '{}'", getLogPrefix(),
                    getConfigurationIdentifier(), e);
            throw new ResolverException("Error refreshing discovery configuration from " + getConfigurationIdentifier(),
                    e);
        } finally {
            lastRefresh = now;
            // The initial cycle is scheduled by doInitialize() once it is known to have
            // succeeded.
            if (isInitialized()) {
                scheduleNextRefresh(nextDelay);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        try {
            refresh();
        } catch (final ResolverException e) {
            throw new ComponentInitializationException(
                    getLogPrefix() + " Could not perform the initial load of the discovery configuration", e);
        }
        scheduleNextRefresh(refreshInterval);
    }

    /** {@inheritDoc} */
    @Override
    protected void doDestroy() {
        if (refreshTask != null) {
            refreshTask.cancel();
            refreshTask = null;
        }
        if (createdOwnTaskTimer) {
            taskTimer.cancel();
        }
        configuration = null;

        super.doDestroy();
    }

    /**
     * Schedule the next refresh cycle, unless background refresh has been disabled.
     *
     * @param delay delay before the next cycle
     */
    protected void scheduleNextRefresh(@Nonnull final Duration delay) {
        if (delay.isZero() || delay.isNegative()) {
            log.debug("{} Background refresh disabled for '{}'", getLogPrefix(), getConfigurationIdentifier());
            return;
        }
        refreshTask = new RefreshTask();
        taskTimer.schedule(refreshTask, delay.toMillis());
        log.debug("{} Next refresh cycle for '{}' will occur at '{}'", getLogPrefix(), getConfigurationIdentifier(),
                Instant.now().plus(delay));
    }

    /**
     * Parse fetched bytes into a {@link DiscoveryConfiguration}.
     *
     * @param bytes the fetched configuration
     * @return the parsed configuration
     * @throws ResolverException        if the bytes cannot be turned into a
     *                                  discovery configuration
     * @throws IllegalArgumentException if the bytes are not a valid discovery
     *                                  configuration
     */
    @Nonnull
    protected DiscoveryConfiguration parseConfiguration(@Nonnull final byte[] bytes) throws ResolverException {
        return DiscoveryConfiguration.parse(new String(bytes, StandardCharsets.UTF_8));
    }

    /**
     * Hook called after a newly fetched configuration has become effective. Does
     * nothing by default.
     *
     * @param bytes the bytes the configuration was parsed from
     */
    protected void onConfigurationUpdated(@Nonnull final byte[] bytes) {
    }

    /**
     * Read an input stream into a byte array, closing the stream.
     *
     * @param input stream to read
     * @return the contents of the stream
     * @throws IOException if the stream cannot be read
     */
    @Nonnull
    protected byte[] inputStreamToByteArray(@Nonnull final InputStream input) throws IOException {
        try (input) {
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            final byte[] buffer = new byte[4096];
            int count = input.read(buffer);
            while (count != -1) {
                output.write(buffer, 0, count);
                count = input.read(buffer);
            }
            return output.toByteArray();
        }
    }

    /**
     * Get an identifier for the source, for log messages.
     *
     * @return identifier for the source
     */
    @Nonnull
    protected abstract String getConfigurationIdentifier();

    /**
     * Fetch the configuration from its source.
     *
     * @return the fetched configuration, or null if unchanged since the last fetch
     * @throws ResolverException if the configuration cannot be fetched
     */
    @Nullable
    protected abstract byte[] fetchConfiguration() throws ResolverException;

    /**
     * Get a string to be prepended to log messages.
     *
     * @return "Discovery configuration resolver '&lt;id&gt;':"
     */
    @Nonnull
    @NotEmpty
    protected String getLogPrefix() {
        final String prefix = logPrefix;
        if (prefix != null) {
            return prefix;
        }
        final String id = getId();
        if (id == null) {
            return "Discovery configuration resolver:";
        }
        final String built = "Discovery configuration resolver '" + id + "':";
        logPrefix = built;
        return built;
    }

    /** Background task that refreshes the configuration. */
    private class RefreshTask extends TimerTask {

        /** {@inheritDoc} */
        @Override
        public void run() {
            try {
                if (isDestroyed() || !isInitialized()) {
                    return;
                }
                refresh();
            } catch (final ResolverException e) {
                // Already logged by refresh().
                return;
            }
        }
    }
}
