
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
package org.wso2.securevault.secret;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.definition.IdentityKeyStoreInformation;
import org.wso2.securevault.definition.KeyStoreInformationFactory;
import org.wso2.securevault.definition.TrustKeyStoreInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import java.util.Properties;

/**
 * Entry point for manage secrets
 */
public class SecretManager {

    private static Log log = LogFactory.getLog(SecretManager.class);

    private final static SecretManager SECRET_MANAGER = new SecretManager();

    /* Default configuration file path for secret manager*/
    private final static String PROP_DEFAULT_CONF_LOCATION = "secret-manager.properties";
    /* If the location of the secret manager configuration is provided as a property- it's name */
    private final static String PROP_SECRET_MANAGER_CONF = "secret.manager.conf";
    /* Property key for secretRepositories*/
    private final static String PROP_SECRET_REPOSITORIES = "secretRepositories";
    private final static String PROP_SECRET_MANAGER_ENABLED = "secVault.enabled";
    /* Type of the secret repository */
    private final static String PROP_PROVIDER = "provider";
    /* Dot string */
    private final static String DOT = ".";
    /* Property key for secretRepositoryProviders */
    private final static String PROP_SECRET_PROVIDERS = "secretRepositoryProviders";
    /* To amend to the key name of the allProviders map when adding multiple providers */
    private final static int STARTING_VALUE = 1;
    /* To amend to the key name of the allProviders map when adding providers which are under secretRepository
    properties */
    private final static String SECRET_REPOSITORY = "secretRepository";
    /* To amend to the key name of the allProviders map when adding providers which are under secretRepositoryProviders
    properties */
    private final static String SECRET_REPOSITORY_PROVIDER = "secretRepositoryProvider";
    /* to split the secret annotation */
    private final static String DELIMITER = ":";

    /*Root Secret Repository */
    private SecretRepository parentRepository;
    /* True , if secret manage has been started up properly- need to have a at
    least one Secret Repository*/
    private boolean initialized = false;

    // global password provider implementation class if defined in secret manager conf file
    private String globalSecretProvider =null;
    // property key for global secret provider
    private final static String PROP_SECRET_PROVIDER="carbon.secretProvider";


    /* get all the vault repository providers to a Hash Map */
    HashMap<String,String> allProviders = new HashMap<>();
    /* get all the vault repositories to a Hash Map */
    HashMap<String,SecretRepository> allExternalRepositories = new HashMap<>();

    /* Branch out to existing securevault implementation */
    private Boolean repoExists = true;
    /* Branch out to new implementation of the securevault */
    private Boolean providerExists = true;
    /* To get the repositories listed under secretRepositories property */
    private String[] repositories;
    /* To get the providers listed under secretRepositoryProviders property */
    private String[] externalProviders;
    /* Key from set of the keys of allProviders Hashmap */
    private String allProviderKey;
    /* Value from set of the values of allProviders Hashmap */
    private String allProviderValue;


    public static SecretManager getInstance() {
        return SECRET_MANAGER;
    }

    private SecretManager() {
    }

    /**
     * Initializes the Secret Manager by providing configuration properties
     *
     * @param properties Configuration properties
     */
    public void init(Properties properties) {

        if (initialized) {
            if (log.isDebugEnabled()) {
                log.debug("Secret Manager already has been started.");
            }
            return;
        }

        if (properties == null) {
            if (log.isDebugEnabled()) {
                log.debug("KeyStore configuration properties cannot be found");
            }
            return;
        }

        String configurationFile = MiscellaneousUtil.getProperty(
                properties, PROP_SECRET_MANAGER_CONF, PROP_DEFAULT_CONF_LOCATION);

        Properties configurationProperties = MiscellaneousUtil.loadProperties(configurationFile);
        if (configurationProperties == null || configurationProperties.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Configuration properties can not be loaded form : " +
                        configurationFile + " Will use synapse properties");
            }
            configurationProperties = properties;

        }

        String enable = MiscellaneousUtil.getProperty(configurationProperties, PROP_SECRET_MANAGER_ENABLED, "true");
        if (!Boolean.parseBoolean(enable)) {
            return;
        }

        globalSecretProvider = MiscellaneousUtil.getProperty(configurationProperties, PROP_SECRET_PROVIDER,null);
        if(globalSecretProvider==null || "".equals(globalSecretProvider)){
            if(log.isDebugEnabled()){
                log.debug("No global secret provider is configured.");
            }
        }

        String repositoriesString = MiscellaneousUtil.getProperty(
                configurationProperties, PROP_SECRET_REPOSITORIES, null);
        if ((repositoriesString == null || "".equals(repositoriesString))){
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            repoExists = false;
        }

        String externalProviderString = MiscellaneousUtil.getProperty(
                configurationProperties, PROP_SECRET_PROVIDERS, null);
        if ((externalProviderString == null || "".equals(externalProviderString))){
            if (log.isDebugEnabled()) {
                log.debug("No external secret repositories have been configured");
            }
            providerExists = false;
        }

        if ( !(repoExists || providerExists)){
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return;
        }


        if ( repoExists ){
            repositories = repositoriesString.split(",");
            if (repositories == null || repositories.length == 0 ){
                if (log.isDebugEnabled()) {
                    log.debug("No secret repositories have been configured");
                }
                repoExists = false;
            }
            int repoCounter = STARTING_VALUE;
            for(String repo : repositories){
                allProviders.put(SECRET_REPOSITORY+repoCounter,repo);
                repoCounter++;
            }
        }

        if( providerExists ){
            externalProviders = externalProviderString.split(",");
            if (externalProviders == null || externalProviders.length == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("No external secret repositories have been configured");
                }
                providerExists = false;
            }
            int extProviderCounter = STARTING_VALUE;
            for(String extProvider : externalProviders){
                allProviders.put(SECRET_REPOSITORY_PROVIDER+extProviderCounter,extProvider);
                extProviderCounter++;
            }
        }

        if (!(repoExists || providerExists) ) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return;
        }

        IdentityKeyStoreWrapper identityKeyStoreWrapper = null;
        TrustKeyStoreWrapper trustKeyStoreWrapper = null;
        if (repoExists){
            //Create a KeyStore Information  for private key entry KeyStore
            IdentityKeyStoreInformation identityInformation =
                    KeyStoreInformationFactory.createIdentityKeyStoreInformation(properties);

            // Create a KeyStore Information for trusted certificate KeyStore
            TrustKeyStoreInformation trustInformation =
                    KeyStoreInformationFactory.createTrustKeyStoreInformation(properties);

            String identityKeyPass = null;
            String identityStorePass = null;
            String trustStorePass = null;
            if(identityInformation != null){
                identityKeyPass = identityInformation
                        .getKeyPasswordProvider().getResolvedSecret();
                identityStorePass = identityInformation
                        .getKeyStorePasswordProvider().getResolvedSecret();
            }

            if(trustInformation != null){
                trustStorePass = trustInformation
                        .getKeyStorePasswordProvider().getResolvedSecret();
            }


            if (!validatePasswords(identityStorePass, identityKeyPass, trustStorePass)) {
                if (log.isDebugEnabled()) {
                    log.info("Either Identity or Trust keystore password is mandatory" +
                            " in order to initialized secret manager.");
                }
                return;
            }

            identityKeyStoreWrapper = new IdentityKeyStoreWrapper();
            identityKeyStoreWrapper.init(identityInformation, identityKeyPass);

            trustKeyStoreWrapper = new TrustKeyStoreWrapper();
            if(trustInformation != null){
                trustKeyStoreWrapper.init(trustInformation);
            }

        }

        SecretRepository currentParent = null;
        for(Map.Entry singleProvider : allProviders.entrySet()){
            allProviderKey = (String) singleProvider.getKey();
            allProviderValue = (String) singleProvider.getValue();

            StringBuffer sb = new StringBuffer();
            if (allProviderKey.contains(SECRET_REPOSITORY_PROVIDER)){
                sb.append(PROP_SECRET_PROVIDERS);

            }else{
                sb.append(PROP_SECRET_REPOSITORIES);
            }
            sb.append(DOT);
            sb.append(allProviderValue);
            String id = sb.toString();
            sb.append(DOT);
            sb.append(PROP_PROVIDER);

            String provider = MiscellaneousUtil.getProperty(
                    configurationProperties, sb.toString(), null);
            if (provider == null || "".equals(provider)) {
                handleException("Repository provider cannot be null ");
            }

            if (log.isDebugEnabled()) {
                log.debug("Initiating a Secret Repository");
            }

            try {

                Class aClass = getClass().getClassLoader().loadClass(provider.trim());
                Object instance = aClass.newInstance();

                if (instance instanceof SecretRepositoryProvider) {
                    if (allProviderKey.contains(SECRET_REPOSITORY_PROVIDER)) {
                        String externalRepositoriesString = MiscellaneousUtil.getProperty(
                                configurationProperties, allProviderValue + PROP_SECRET_REPOSITORIES, null);
                        if (externalRepositoriesString == null || "".equals(externalRepositoriesString)) {
                            if (log.isDebugEnabled()) {
                                log.debug("No repositories have been configured");
                            }
                            return;
                        }

                        String[] externalRepositoriesArr = externalRepositoriesString.split(",");
                        if (externalRepositoriesArr == null || externalRepositoriesArr.length == 0) {
                            if (log.isDebugEnabled()) {
                                log.debug("No repositories have been configured");
                            }
                            return;
                        }
                        allExternalRepositories =
                                ((SecretRepositoryProvider) instance).initProvider(externalRepositoriesArr,
                                        configurationProperties, allProviderValue);

                        if (log.isDebugEnabled()) {
                            log.debug("Successfully Initiate a Secret Repository provided by : "
                                    + provider);
                        }

                    } else{
                        SecretRepository secretRepository = ((SecretRepositoryProvider) instance).
                                getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
                        secretRepository.init(configurationProperties, id);
                        if (parentRepository == null) {
                            parentRepository = secretRepository;
                        }
                        secretRepository.setParent(currentParent);
                        currentParent = secretRepository;

                        if (log.isDebugEnabled()) {
                            log.debug("Successfully Initiate a Secret Repository provided by : "
                                    + provider);
                        }

                    }
                }else {
                        handleException("Invalid class as SecretRepositoryProvider : Class Name : "
                                + provider);
                }

            } catch (ClassNotFoundException e) {
                handleException("A Secret Provider cannot be found for class name : " + provider);
            } catch (IllegalAccessException e) {
                handleException("Error creating a instance from class : " + provider);
            } catch (InstantiationException e) {
                handleException("Error creating a instance from class : " + provider);
            }

        }
        initialized = true;
    }

    /**
     *
     * @param alias      alias to be resolved
     * @return If there is a secret , otherwise , alias itself
     */
    public String getSecret(String alias) {
                if (!initialized || parentRepository == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("There is no secret repository. Returning alias itself");
                    }
                    return alias;
                }
                return parentRepository.getSecret(alias);
            }

    /**
     *
     * @param provider   provider type
     * @param repository repository type
     * @param alias      alias to be resolved
     * @return If there is a secret , otherwise , alias itself
     */
    private String getSecret(String provider,String repository,String alias) {
        if (allProviders.containsValue(provider) && allExternalRepositories.containsKey(repository)){
            return allExternalRepositories.get(repository).getSecret(alias);
        }
        if (log.isDebugEnabled()) {
            log.debug("No such secret repository listed under configurations");
        }
        return alias;

    }

    /**
     *
     * @param secretAnnotation String contains the alias, the provider type and the repository type
     * @return plain text value for the required secret
     */
    public String checker( String secretAnnotation ){
        String provider, repository, alias;

        String[] parts = secretAnnotation.split(DELIMITER);
        if (parts.length ==1){
            if (repoExists){
                return getSecret(secretAnnotation);
            }else{
                provider = allProviderValue;
                repository = (String) allExternalRepositories.keySet().toArray()[0];
                alias = secretAnnotation;

                return getSecret(provider,repository,alias);
            }
        }else {
            provider = parts[0];
            repository = parts[1];
            alias = parts[2];

            return getSecret(provider,repository,alias);
        }
    }

    /**
     * Returns the encrypted value corresponding to the given alias name
     *
     * @param alias The logical or alias name
     * @return If there is a encrypted value , otherwise , alias itself
     */
    public String getEncryptedData(String alias) {
        if (!initialized || parentRepository == null) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret repository. Returning alias itself");
            }
            return alias;
        }
        return parentRepository.getEncryptedData(alias);
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void shoutDown() {
        this.parentRepository = null;
        this.initialized = false;
    }

    private static void handleException(String msg) {
        log.error(msg);
        throw new SecureVaultException(msg);
    }

    private boolean validatePasswords(String identityStorePass,
                                      String identityKeyPass, String trustStorePass) {
        boolean isValid = false;
        if (trustStorePass != null && !"".equals(trustStorePass)) {
            if (log.isDebugEnabled()) {
                log.debug("Trust Store Password cannot be found.");
            }
            isValid = true;
        } else {
            if (identityStorePass != null && !"".equals(identityStorePass) &&
                    identityKeyPass != null && !"".equals(identityKeyPass)) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity Store Password " +
                            "and Identity Store private key Password cannot be found.");
                }
                isValid = true;
            }
        }
        return isValid;
    }

    public String getGlobalSecretProvider() {
        return globalSecretProvider;
    }
}
