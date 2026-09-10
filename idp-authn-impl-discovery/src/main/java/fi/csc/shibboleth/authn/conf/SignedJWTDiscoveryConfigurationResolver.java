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

import java.util.Map;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.opensaml.security.SecurityException;

import net.shibboleth.shared.annotation.ParameterName;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.logic.Constraint;
import net.shibboleth.shared.primitive.StringSupport;
import net.shibboleth.shared.resolver.ResolverException;

/**
 * A {@link FileBackedHTTPDiscoveryConfigurationResolver} that asks for the
 * configuration as a signed JWT and unwraps it. The backup file holds the token
 * as received, so a configuration recovered from it is signature checked too.
 *
 * <p>
 * By default the whole payload is the configuration object. Set
 * {@link #setConfigurationClaim(String)} to nest it under a claim of that name
 * instead.
 * </p>
 */
public class SignedJWTDiscoveryConfigurationResolver extends FileBackedHTTPDiscoveryConfigurationResolver {

    /** Default value of the Accept header. */
    @Nonnull
    public static final String DEFAULT_ACCEPT_HEADER = "application/jwt";

    /** Verifier that checks the signature of a fetched token. */
    @Nullable
    private SignedJWTVerifier verifier;

    /** Value of the Accept header sent with the request. */
    @Nonnull
    private String acceptHeader;

    /**
     * Claim holding the discovery configuration, or null when the whole payload is
     * the configuration.
     */
    @Nullable
    private String configurationClaim;

    /**
     * Constructor.
     *
     * @param client         HTTP client used to fetch the token
     * @param url            URL the token is fetched from
     * @param backupFilePath path of the file holding the backup copy of the token
     * @throws ResolverException if the URL is not valid
     */
    public SignedJWTDiscoveryConfigurationResolver(@Nonnull @ParameterName(name = "client") final HttpClient client,
            @Nonnull @ParameterName(name = "url") final String url,
            @Nonnull @ParameterName(name = "backupFilePath") final String backupFilePath) throws ResolverException {
        this(null, client, url, backupFilePath);
    }

    /**
     * Constructor.
     *
     * @param backgroundTaskTimer timer used to schedule background refresh tasks,
     *                            or null to create a private one
     * @param client              HTTP client used to fetch the token
     * @param url                 URL the token is fetched from
     * @param backupFilePath      path of the file holding the backup copy of the
     *                            token
     * @throws ResolverException if the URL is not valid
     */
    public SignedJWTDiscoveryConfigurationResolver(
            @Nullable @ParameterName(name = "backgroundTaskTimer") final Timer backgroundTaskTimer,
            @Nonnull @ParameterName(name = "client") final HttpClient client,
            @Nonnull @ParameterName(name = "url") final String url,
            @Nonnull @ParameterName(name = "backupFilePath") final String backupFilePath) throws ResolverException {
        super(backgroundTaskTimer, client, url, backupFilePath);

        acceptHeader = DEFAULT_ACCEPT_HEADER;
    }

    /**
     * Set the verifier that checks the signature of a fetched token.
     *
     * @param jwtVerifier what to set
     */
    public void setVerifier(@Nonnull final SignedJWTVerifier jwtVerifier) {
        checkSetterPreconditions();

        verifier = Constraint.isNotNull(jwtVerifier, "Verifier cannot be null");
    }

    /**
     * Set the value of the Accept header, defaults to
     * {@value #DEFAULT_ACCEPT_HEADER}.
     *
     * @param value what to set
     */
    public void setAcceptHeader(@Nonnull final String value) {
        checkSetterPreconditions();

        acceptHeader = Constraint.isNotNull(StringSupport.trimOrNull(value), "Accept header cannot be null or empty");
    }

    /**
     * Set the claim holding the configuration. Unset means the whole payload is the
     * configuration.
     *
     * @param claim what to set
     */
    public void setConfigurationClaim(@Nullable final String claim) {
        checkSetterPreconditions();

        configurationClaim = StringSupport.trimOrNull(claim);
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        // Checked before the superclass performs its initial load.
        if (verifier == null) {
            throw new ComponentInitializationException("A SignedJWTVerifier is required");
        }
        verifier.initialize();

        super.doInitialize();
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected HttpGet buildHttpGet() {
        final HttpGet httpGet = super.buildHttpGet();
        httpGet.setHeader("Accept", acceptHeader);
        return httpGet;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected DiscoveryConfiguration parseConfiguration(@Nonnull final byte[] bytes) throws ResolverException {
        assert verifier != null;

        final Map<String, Object> claims;
        try {
            claims = verifier.verify(bytes);
        } catch (final SecurityException e) {
            throw new ResolverException(
                    "Discovery configuration token from " + getConfigurationIdentifier() + " was rejected", e);
        }

        final String claim = configurationClaim;
        if (claim == null) {
            return DiscoveryConfiguration.parse(claims);
        }

        final Object configuration = claims.get(claim);
        if (configuration == null) {
            throw new ResolverException("Discovery configuration token from " + getConfigurationIdentifier()
                    + " has no '" + claim + "' claim");
        }
        return DiscoveryConfiguration.parse(configuration);
    }
}
