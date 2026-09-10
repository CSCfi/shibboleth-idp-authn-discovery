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

import java.time.Instant;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.component.IdentifiedComponent;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.service.ReloadableService;

/**
 * A source of {@link DiscoveryConfiguration} that refreshes itself. A failed
 * refresh leaves the configuration in effect untouched. {@link #reload()} is
 * {@link #refresh()} with an unchecked exception.
 */
public interface DiscoveryConfigurationResolver extends IdentifiedComponent, ReloadableService<DiscoveryConfiguration> {

    /**
     * Get the configuration in effect.
     *
     * @return the configuration in effect
     * @throws IllegalStateException if there is none, meaning before initialization
     *                               or after destruction
     */
    @Nonnull
    DiscoveryConfiguration resolve();

    /**
     * Refresh the configuration from its source.
     *
     * @throws ResolverException if the refresh failed
     */
    void refresh() throws ResolverException;

    /**
     * Get the time of the last refresh cycle.
     *
     * @return time of the last refresh cycle, or null
     */
    @Nullable
    Instant getLastRefresh();

    /**
     * Get the time of the last successful refresh cycle.
     *
     * @return time of the last successful refresh cycle, or null
     */
    @Nullable
    Instant getLastSuccessfulRefresh();

    /**
     * Get the time the configuration in effect was last replaced.
     *
     * @return time the configuration in effect was last replaced, or null
     */
    @Nullable
    Instant getLastUpdate();

    /**
     * Get the reason the last refresh failed.
     *
     * @return reason the last refresh failed, or null
     */
    @Nullable
    Throwable getLastFailureCause();
}
