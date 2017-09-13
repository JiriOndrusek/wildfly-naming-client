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
import static org.jboss.naming.remote.client.InitialContextFactory.CALLBACK_HANDLER_KEY;
import static org.jboss.naming.remote.client.InitialContextFactory.ENDPOINT;
import static org.jboss.naming.remote.client.InitialContextFactory.PASSWORD_BASE64_KEY;
import static org.jboss.naming.remote.client.InitialContextFactory.REALM_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.CONNECT_OPTIONS;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_CALLBACK_HANDLER_CLASS_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_PASSWORD_BASE64_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_PASSWORD_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_REMOTE_CONNECTION_PREFIX;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_USERNAME_KEY;

import java.net.URI;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.security.auth.callback.CallbackHandler;

import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.RemotingOptions;
import org.kohsuke.MetaInfServices;
import org.wildfly.common.expression.Expression;
import org.wildfly.naming.client.NamingProvider.Location;
import org.wildfly.naming.client.NamingProviderFactory;
import org.wildfly.naming.client._private.Messages;
import org.wildfly.naming.client.util.FastHashtable;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.sasl.localuser.LocalUserClient;
import org.wildfly.security.util.CodePointIterator;
import org.xnio.Option;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.Property;
import org.xnio.Sequence;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices
public final class RemoteNamingProviderFactory implements NamingProviderFactory {
    public RemoteNamingProviderFactory() {
    }

    private static final String CONNECT_OPTIONS_PREFIX = "jboss.naming.client.connect.options.";
    private static final String NAMING_CLIENT_PREFIX = "jboss.naming.client.";
    private static final OptionMap DEFAULT_CONNECTION_CREATION_OPTIONS = OptionMap.create(Options.SASL_POLICY_NOANONYMOUS, false);

    public boolean supportsUriScheme(final String providerScheme, final FastHashtable<String, Object> env) {
        final Endpoint endpoint = getEndpoint(env);
        return endpoint != null && endpoint.isValidUriScheme(providerScheme);
    }

    public RemoteNamingProvider createProvider(final FastHashtable<String, Object> env, final URI... providerUris) throws NamingException {
        final ClassLoader classLoader = secureGetContextClassLoader();
        final Properties properties = getPropertiesFromEnv(env);

        // Legacy naming constants
        final Endpoint endpoint = getEndpoint(env);
        final String callbackClass = getProperty(properties, CALLBACK_HANDLER_KEY, null, true);
        final String userName = getProperty(properties, Context.SECURITY_PRINCIPAL, null, true);
        final String password = getProperty(properties, Context.SECURITY_CREDENTIALS, null, false);
        final String passwordBase64 = getProperty(properties, PASSWORD_BASE64_KEY, null, false);
        final String realm = getProperty(properties, REALM_KEY, null, true);
        final OptionMap configuredConnectOptions = getOptionMapFromProperties(properties, CONNECT_OPTIONS_PREFIX, classLoader);
        OptionMap connectOptions = mergeWithDefaultOptionMap(DEFAULT_CONNECTION_CREATION_OPTIONS, configuredConnectOptions);

        CallbackHandler callbackHandler = null;
        String decodedPassword = null;
        if (callbackClass != null && (userName != null || password != null)) {
            throw Messages.log.callbackHandlerAndUsernameAndPasswordSpecified();
        }
        if (callbackClass != null) {
            try {
                final Class<?> clazz = Class.forName(callbackClass, true, classLoader);
                callbackHandler = (CallbackHandler) clazz.newInstance();
            } catch (ClassNotFoundException e) {
                throw Messages.log.failedToLoadCallbackHandlerClass(e, callbackClass);
            } catch (Exception e) {
                throw Messages.log.failedToInstantiateCallbackHandlerInstance(e, callbackClass);
            }
        } else if (userName != null) {
            if (password != null && passwordBase64 != null) {
                throw Messages.log.plainTextAndBase64PasswordSpecified();
            }
            decodedPassword = passwordBase64 != null ? CodePointIterator.ofString(passwordBase64).base64Decode().asUtf8String().drainToString() : password;
        }

        if (callbackHandler != null || userName != null) {
            // disable quiet local auth
            connectOptions = setQuietLocalAuth(connectOptions, false);
        }

        List<Location> locationList = new ArrayList<>(providerUris.length);

        for (URI providerUri : providerUris) {
            AuthenticationConfiguration authenticationConfiguration = RemotingOptions.mergeOptionsIntoAuthenticationConfiguration(connectOptions, AuthenticationConfiguration.empty());

            if (callbackHandler != null) {
                authenticationConfiguration = authenticationConfiguration.useCallbackHandler(callbackHandler);
            } else if (userName != null) {
                authenticationConfiguration = authenticationConfiguration.useName(userName).usePassword(decodedPassword).useRealm(realm);
            }

            if (! authenticationConfiguration.equals(AuthenticationConfiguration.empty())) {
                locationList.add(Location.of(providerUri, authenticationConfiguration, null));
            } else {
                locationList.add(Location.of(providerUri));
            }
        }
        return new RemoteNamingProvider(endpoint, locationList, env);
    }

    private Endpoint getEndpoint(final FastHashtable<String, Object> env) {
        return env.containsKey(ENDPOINT) ? (Endpoint) env.get(ENDPOINT) : Endpoint.getCurrent();
    }

    private static Properties getPropertiesFromEnv(final FastHashtable<String, Object> env) {
        Properties properties = new Properties();
        for (Map.Entry<String, Object> entry : env.entrySet()) {
            if (entry.getValue() instanceof String) {
                properties.setProperty(processPropertyName(entry.getKey()), (String) entry.getValue());
            }
        }
        return properties;
    }

    private static String getProperty(final Properties properties, final String propertyName, final String defaultValue, final boolean expand) {
        final String str = properties.getProperty(propertyName);
        if (str == null) {
            return defaultValue;
        }
        if (expand) {
            final Expression expression = Expression.compile(str, Expression.Flag.LENIENT_SYNTAX);
            return expression.evaluateWithPropertiesAndEnvironment(false);
        } else {
            return str.trim();
        }
    }

    private static boolean getBooleanValueFromProperties(final Properties properties, final String propertyName, final boolean defVal) {
        final String str = getProperty(properties, propertyName, null, true);
        if (str == null) {
            return defVal;
        }
        return Boolean.parseBoolean(str);
    }

    private static OptionMap getOptionMapFromProperties(final Properties properties, final String propertyPrefix, final ClassLoader classLoader) {
        return OptionMap.builder().parseAll(properties, propertyPrefix, classLoader).getMap();
    }

    private static String processPropertyName(String propertyName) {
        // convert an EJB remote connection property name to an equivalent naming property name, where possible
        if (propertyName.startsWith(EJB_REMOTE_CONNECTION_PREFIX)) {
            if (propertyName.endsWith(EJB_CALLBACK_HANDLER_CLASS_KEY)) {
                propertyName = CALLBACK_HANDLER_KEY;
            } else if (propertyName.endsWith(EJB_USERNAME_KEY)) {
                propertyName = Context.SECURITY_PRINCIPAL;
            } else if (propertyName.endsWith(EJB_PASSWORD_KEY)) {
                propertyName = Context.SECURITY_CREDENTIALS;
            } else if (propertyName.endsWith(EJB_PASSWORD_BASE64_KEY)) {
                propertyName = PASSWORD_BASE64_KEY;
            } else if (propertyName.contains(CONNECT_OPTIONS)) {
                propertyName = NAMING_CLIENT_PREFIX + propertyName.substring(propertyName.indexOf(CONNECT_OPTIONS));
            }
        }
        return propertyName;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static OptionMap mergeWithDefaultOptionMap(final OptionMap defaultOptions, final OptionMap configuredOptions) {
        final OptionMap.Builder mergedOptionMapBuilder = OptionMap.builder().addAll(configuredOptions);
        for (Option defaultOption : defaultOptions) {
            if (mergedOptionMapBuilder.getMap().contains(defaultOption)) {
                // skip this option since it's already been configured
                continue;
            }
            // add this default option to the merged option map
            mergedOptionMapBuilder.set(defaultOption, defaultOptions.get(defaultOption));
        }
        return mergedOptionMapBuilder.getMap();
    }

    private static ClassLoader secureGetContextClassLoader() {
        final ClassLoader contextClassLoader;
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            contextClassLoader = doPrivileged((PrivilegedAction<ClassLoader>) RemoteNamingProviderFactory::getContextClassLoader);
        } else {
            contextClassLoader = getContextClassLoader();
        }
        return contextClassLoader;
    }

    private static ClassLoader getContextClassLoader() {
        return Thread.currentThread().getContextClassLoader();
    }

    /**
     * Set the quiet local auth property to the given value if the user hasn't already set this property.
     *
     * @param optionMap the option map
     * @param useQuietAuth the value to set the quiet local auth property to
     * @return the option map with the quiet local auth property set to the given value if the user hasn't already set this property
     */
    private static OptionMap setQuietLocalAuth(final OptionMap optionMap, final boolean useQuietAuth) {
        final Sequence<Property> existingSaslProps = optionMap.get(Options.SASL_PROPERTIES);
        if (existingSaslProps != null) {
            for (Property prop : existingSaslProps) {
                final String propKey = prop.getKey();
                if (propKey.equals(LocalUserClient.QUIET_AUTH) || propKey.equals(LocalUserClient.LEGACY_QUIET_AUTH)) {
                    // quiet local auth property was already set, do not override it
                    return optionMap;
                }
            }
            // set the quiet local auth property since it wasn't already set in SASL_PROPERTIES
            existingSaslProps.add(Property.of(LocalUserClient.QUIET_AUTH, Boolean.toString(useQuietAuth)));
            return optionMap;
        }
        // set the quiet local auth property since no SASL_PROPERTIES were set
        final OptionMap.Builder updatedOptionMapBuilder = OptionMap.builder().addAll(optionMap);
        updatedOptionMapBuilder.set(Options.SASL_PROPERTIES, Sequence.of(Property.of(LocalUserClient.QUIET_AUTH, Boolean.toString(useQuietAuth))));
        return updatedOptionMapBuilder.getMap();
    }
}
