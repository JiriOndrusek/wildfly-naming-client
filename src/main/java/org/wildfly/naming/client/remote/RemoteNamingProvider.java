/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.naming.client.remote;

import static java.security.AccessController.doPrivileged;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.List;

import javax.naming.NamingException;
import javax.net.ssl.SSLContext;

import org.jboss.remoting3.ConnectionPeerIdentity;
import org.jboss.remoting3.Endpoint;
import org.wildfly.common.Assert;
import org.wildfly.naming.client.NamingProvider;
import org.wildfly.naming.client._private.Messages;
import org.wildfly.naming.client.util.FastHashtable;
import org.wildfly.security.auth.AuthenticationException;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.xnio.FailedIoFuture;
import org.xnio.IoFuture;

/**
 * A provider for JBoss Remoting-based JNDI contexts.  Any scheme which uses JBoss Remoting using this provider will
 * share a connection and a captured security context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class RemoteNamingProvider implements NamingProvider {

    private static final AuthenticationContextConfigurationClient CLIENT = doPrivileged(AuthenticationContextConfigurationClient.ACTION);
    private final Endpoint endpoint;
    private final List<Location> locationsList;

    RemoteNamingProvider(final Endpoint endpoint, final List<Location> locationsList, final FastHashtable<String, Object> env) {
        this.endpoint = endpoint;
        this.locationsList = locationsList;
    }

    /**
     * Get the Remoting endpoint for this provider.
     *
     * @return the Remoting endpoint for this provider (not {@code null})
     */
    public Endpoint getEndpoint() {
        return endpoint;
    }

    public List<Location> getLocations() {
        return locationsList;
    }

    /**
     * Get the connection peer identity for a naming operation.  If the connection is not configured as {@code immediate}, then the connection
     * will not actually be established until this method is called.  The resultant connection should be closed and
     * discarded in the event of an error, in order to facilitate automatic reconnection.
     *
     * @return the connection peer identity (not {@code null})
     * @throws NamingException if connecting, authenticating, or re-authenticating the peer failed
     */
    public ConnectionPeerIdentity getPeerIdentityForNaming() throws NamingException {
        return (ConnectionPeerIdentity) NamingProvider.super.getPeerIdentityForNaming();
    }

    /**
     * Get the connection peer identity for a naming operation.  If the connection is not configured as {@code immediate}, then the connection
     * will not actually be established until this method is called.  The resultant connection should be closed and
     * discarded in the event of an error, in order to facilitate automatic reconnection.
     *
     * @param location a location from {@link #getLocations()} (must not be {@code null})
     * @return the connection peer identity (not {@code null})
     * @throws NamingException if connecting, authenticating, or re-authenticating the peer failed
     */
    public ConnectionPeerIdentity getPeerIdentityForNaming(final Location location) throws NamingException {
        Assert.checkNotNullParam("location", location);
        try {
            return getPeerIdentity(location);
        } catch (AuthenticationException e) {
            throw Messages.log.authenticationFailed(e);
        } catch (IOException e) {
            throw Messages.log.connectFailed(e);
        }
    }

    /**
     * Get the connection peer identity.  If the connection is not configured as {@code immediate}, then the connection
     * will not actually be established until this method is called.  The resultant connection should be closed and
     * discarded in the event of an error, in order to facilitate automatic reconnection.
     *
     * @param location a location from {@link #getLocations()} (must not be {@code null})
     * @return the connection peer identity (not {@code null})
     * @throws AuthenticationException if authenticating or re-authenticating the peer failed
     * @throws IOException if connecting the peer failed
     */
    public ConnectionPeerIdentity getPeerIdentity(Location location) throws IOException {
        Assert.checkNotNullParam("location", location);
        return getFuturePeerIdentity(location).get();
    }

    /**
     * Get the future connection peer identity.  If the connection is not configured as {@code immediate}, then the connection
     * will not actually be established until this method is called.  The resultant connection should be closed and
     * discarded in the event of an error, in order to facilitate automatic reconnection.
     *
     * @return the future connection peer identity (not {@code null})
     */
    public IoFuture<ConnectionPeerIdentity> getFuturePeerIdentity(Location location) {
        return doPrivileged((PrivilegedAction<IoFuture<ConnectionPeerIdentity>>) () -> getFuturePeerIdentityPrivileged(location));
    }

    private IoFuture<ConnectionPeerIdentity> getFuturePeerIdentityPrivileged(Location location) {
        final SSLContext sslContext = location.getSSLContext();
        final URI providerUri = location.getUri();
        final AuthenticationConfiguration authenticationConfiguration = location.getAuthenticationConfiguration();
        final SSLContext realSSLContext;
        if (sslContext == null) {
            try {
                realSSLContext = CLIENT.getSSLContext(providerUri, AuthenticationContext.captureCurrent(), "jndi", "jboss");
            } catch (GeneralSecurityException e) {
                return new FailedIoFuture<>(new IOException(e));
            }
        } else {
            realSSLContext = sslContext;
        }
        final AuthenticationConfiguration realConf;
        if (authenticationConfiguration == null) {
            realConf = CLIENT.getAuthenticationConfiguration(providerUri, AuthenticationContext.captureCurrent(), -1, "jndi", "jboss");
        } else {
            realConf = authenticationConfiguration;
        }
        return endpoint.getConnectedIdentity(providerUri, realSSLContext, realConf);
    }
}
