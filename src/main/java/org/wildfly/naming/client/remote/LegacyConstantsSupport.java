package org.wildfly.naming.client.remote;

import org.jboss.remoting3.Endpoint;
import org.jboss.remoting3.RemotingOptions;
import org.wildfly.common.expression.Expression;
import org.wildfly.naming.client.NamingProvider;
import org.wildfly.naming.client._private.Messages;
import org.wildfly.naming.client.util.FastHashtable;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.sasl.localuser.LocalUserClient;
import org.wildfly.security.util.CodePointIterator;
import org.xnio.Option;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.Property;
import org.xnio.Sequence;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.security.auth.callback.CallbackHandler;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.Properties;
import java.util.function.UnaryOperator;

import static java.security.AccessController.doPrivileged;
import static org.jboss.naming.remote.client.InitialContextFactory.CALLBACK_HANDLER_KEY;
import static org.jboss.naming.remote.client.InitialContextFactory.PASSWORD_BASE64_KEY;
import static org.jboss.naming.remote.client.InitialContextFactory.REALM_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.CONNECT_OPTIONS;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_CALLBACK_HANDLER_CLASS_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_PASSWORD_BASE64_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_PASSWORD_KEY;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_REMOTE_CONNECTION_PREFIX;
import static org.wildfly.naming.client.util.EnvironmentUtils.EJB_USERNAME_KEY;

/**
 * Created by jondruse on 9/14/17.
 */
public class LegacyConstantsSupport {

    private static final String NAMING_CLIENT_PREFIX = "jboss.naming.client.";

    public static UnaryOperator<AuthenticationConfiguration> getAuthenticationConfigurationPostProcessor(final FastHashtable<String, Object> env) throws NamingException {
        final ClassLoader classLoader = secureGetContextClassLoader();
        final Properties properties = getPropertiesFromEnv(env);

        // Legacy naming constants
        final String callbackClass = getProperty(properties, CALLBACK_HANDLER_KEY, null, true);
        final String userName = getProperty(properties, Context.SECURITY_PRINCIPAL, null, true);
        final String password = getProperty(properties, Context.SECURITY_CREDENTIALS, null, false);
        final String passwordBase64 = getProperty(properties, PASSWORD_BASE64_KEY, null, false);
        final String realm = getProperty(properties, REALM_KEY, null, true);

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
        final String finalDecodedPassword = decodedPassword;
        final CallbackHandler finalCallbackHandler = callbackHandler;

        if (callbackHandler != null) {
            return a -> {return a.useCallbackHandler(finalCallbackHandler);};
        } else if (userName != null) {
            return a -> {return a.useName(userName).usePassword(finalDecodedPassword).useRealm(realm);};
        } else {
            return null;
        }
    }

    static Properties getPropertiesFromEnv(final FastHashtable<String, Object> env) {
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


    private static ClassLoader secureGetContextClassLoader() {
        final ClassLoader contextClassLoader;
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            contextClassLoader = doPrivileged((PrivilegedAction<ClassLoader>) LegacyConstantsSupport::getContextClassLoader);
        } else {
            contextClassLoader = getContextClassLoader();
        }
        return contextClassLoader;
    }

    private static ClassLoader getContextClassLoader() {
        return Thread.currentThread().getContextClassLoader();
    }
}
