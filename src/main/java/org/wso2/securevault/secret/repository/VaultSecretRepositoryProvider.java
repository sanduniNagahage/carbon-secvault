/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.securevault.secret.repository;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class VaultSecretRepositoryProvider implements SecretRepositoryProvider {

    private static Log log = LogFactory.getLog(VaultSecretRepositoryProvider.class);

    /* Property String for secretProviders.*/
    private final static String PROP_SECRET_PROVIDERS = "secretProviders";

    /* Property String for repositories.*/
    private final static String PROP_REPOSITORIES = "repositories";

    /* Property String for properties.*/
    private final static String PROPERTIES = "properties";

    /* Dot String.*/
    private final static String DOT = ".";

    /* Contains all initialized secret repositories under provider type vault.*/
    private Map<String, SecretRepository> vaultRepositoryMap = new HashMap<>();

    /**
     * @see org.wso2.securevault.secret.SecretRepositoryProvider
     */
    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {

        return null;
    }

    /**
     * Returns a map containing initialized secret repositories corresponds to a give provider type.
     *
     * @param configurationProperties All the properties under secret configuration file.
     * @param providerType            Type of the VaultSecretRepositoryProvider class.
     * @return Initialized secret repository map.
     * @throws SecureVaultException
     */
    @Override
    public Map<String, SecretRepository> initProvider(Properties configurationProperties, String providerType)
            throws SecureVaultException {

        //Get the list of repositories from the secret configurations.
        StringBuilder repositoriesStringPropKey = new StringBuilder()
                .append(PROP_SECRET_PROVIDERS)
                .append(DOT)
                .append(providerType)
                .append(DOT)
                .append(PROP_REPOSITORIES);

        String repositoriesString = getPropertiesFromSecretConfigurations(
                configurationProperties, repositoriesStringPropKey.toString());

        if (isPropValueValidated(repositoriesString)) {
            // Add the list of repositories to an array.
            String[] repositories = repositoriesString.split(",");

            for (String repo : repositories) {
                // Get the property contains the fully qualified class name of the repository.
                StringBuilder repositoryClassNamePropKey = new StringBuilder()
                        .append(repositoriesStringPropKey.toString())
                        .append(DOT)
                        .append(repo);

                String repositoryClassName = getPropertiesFromSecretConfigurations(configurationProperties,
                        repositoryClassNamePropKey.toString());

                if (isPropValueValidated(repositoryClassName)) {
                    try {
                        // Create a new instance of the class.
                        Class repositoryClass = getClass().getClassLoader().loadClass(repositoryClassName.trim());
                        Object repositoryImpl = repositoryClass.newInstance();

                        if (repositoryImpl instanceof SecretRepository) {
                            Properties repositoryProperties = filterConfigurations(configurationProperties, repo);
                            ((SecretRepository) repositoryImpl).init(repositoryProperties, providerType);
                            vaultRepositoryMap.put(repo, (SecretRepository) repositoryImpl);
                        }
                    } catch (ClassNotFoundException e) {
                        throw new SecureVaultException(
                                "A Secret Provider cannot be found for class name : " + repositoryClassName,e);
                    } catch (IllegalAccessException e) {
                        throw new SecureVaultException(
                                "Error creating an instance, Method does not have access to the class : " +
                                        repositoryClassName,e);
                    } catch (InstantiationException e) {
                        throw new SecureVaultException(
                                "Error creating an instance from class : " + repositoryClassName,e);
                    }
                }
            }
        }
        return vaultRepositoryMap;
    }

    /**
     * Return the properties for a provided repository.
     *
     * @param configProperties All the properties under secret configuration file.
     * @param repository       Repository listed under the vault provider.
     * @return Filtered properties.
     */
    private static Properties filterConfigurations(Properties configProperties, String repository) {

        Properties filteredProps = new Properties();
        StringBuilder propertyKeyPrefix = new StringBuilder()
                .append(repository)
                .append(DOT)
                .append(PROPERTIES);

        configProperties.forEach((propKey, propValue) -> {
            if (propKey.toString().contains(propertyKeyPrefix)) {
                filteredProps.put(propKey, propValue);
            }
        });
        return filteredProps;
    }

    /**
     * Util method for getting property values from the secret-conf file.
     *
     * @param secretConfigProps All the properties under secret configuration file.
     * @param propName          Name of the property.
     * @return Returns the value for the give property.
     */
    private static String getPropertiesFromSecretConfigurations(Properties secretConfigProps, String propName) {

        return MiscellaneousUtil.getProperty(secretConfigProps, propName, null);
    }

    /**
     * Validate the property value to avoid the processing of null values.
     *
     * @param propValue Value of the required property.
     * @return Return true if not null.
     */
    private static boolean isPropValueValidated(String propValue) {

        if (propValue == null || "".equals(propValue)) {
            if (log.isDebugEnabled()) {
                log.debug("No value for the requested property " + propValue + " has been configured.");
            }
            return false;
        }
        return true;
    }
}
