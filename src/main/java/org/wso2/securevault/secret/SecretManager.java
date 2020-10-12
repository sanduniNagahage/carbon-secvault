
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

    /*Root Secret Repository */
    private SecretRepository parentRepository;
    /* True , if secret manage has been started up properly- need to have a at
    least one Secret Repository*/
    private boolean initialized = false;

    // global password provider implementation class if defined in secret manager conf file
    private String globalSecretProvider =null;
    // property key for global secret provider
    private final static String PROP_SECRET_PROVIDER="carbon.secretProvider";

    //get all the vault repositories to a Hash Map
    HashMap<String,SecretRepository> allExternalRepositories = new HashMap<>();
    //Secret repository providers list
    String[] providerTypesArr;

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
        if (repositoriesString == null || "".equals(repositoriesString)) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return;
        }

        providerTypesArr = repositoriesString.split(",");
        if (providerTypesArr == null || providerTypesArr.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repository provider has been configured");
            }
            return;
        }

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

        IdentityKeyStoreWrapper identityKeyStoreWrapper = new IdentityKeyStoreWrapper();
        identityKeyStoreWrapper.init(identityInformation, identityKeyPass);

        TrustKeyStoreWrapper trustKeyStoreWrapper = new TrustKeyStoreWrapper();
        if(trustInformation != null){
            trustKeyStoreWrapper.init(trustInformation);            
        }

        SecretRepository currentParent = null;
        for (String secretProvider : providerTypesArr) {

            StringBuffer sb = new StringBuffer();
            sb.append(PROP_SECRET_REPOSITORIES);
            sb.append(DOT);
            sb.append(secretProvider);
            String id = sb.toString();
            sb.append(DOT);
            sb.append(PROP_PROVIDER);

            String providerClass = MiscellaneousUtil.getProperty(
                    configurationProperties, sb.toString(), null);
            if (providerClass == null || "".equals(providerClass)) {
                handleException("Repository provider cannot be null ");
            }

            if (log.isDebugEnabled()) {
                log.debug("Initiating a Secret Repository");
            }

            try {

                Class aClass = getClass().getClassLoader().loadClass(providerClass.trim());
                Object instance = aClass.newInstance();

                if (instance instanceof SecretRepositoryProvider) {
                    if(secretProvider.equals("file")){
                        SecretRepository secretRepository = ((SecretRepositoryProvider) instance).
                                getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
                        secretRepository.init(configurationProperties, id);
                        if (parentRepository == null) {
                            parentRepository = secretRepository;
                        }
                        secretRepository.setParent(currentParent);
                        currentParent = secretRepository;
                    }else{
                        /*repositories other than the file base */
                        String externalRepositoriesString = MiscellaneousUtil.getProperty(
                                configurationProperties, secretProvider+"SecretRepositories", null);
                        if (externalRepositoriesString == null || "".equals(externalRepositoriesString)){
                            if(log.isDebugEnabled()){
                                log.debug("No repositories have been configured");
                            }
                            return;
                        }

                        String[] externalRepositoriesArr = externalRepositoriesString.split(",");
                        if (externalRepositoriesArr == null || externalRepositoriesArr.length == 0){
                            if(log.isDebugEnabled()){
                                log.debug("No repositories have been configured");
                            }
                            return;
                        }
                        allExternalRepositories =
                                ((SecretRepositoryProvider) instance).initProvider(externalRepositoriesArr,
                                configurationProperties, secretProvider);
                    }

                    if (log.isDebugEnabled()) {
                        log.debug("Successfully Initiate a Secret Repository provided by : "
                                + providerClass);
                    }
                } else {
                    handleException("Invalid class as SecretRepositoryProvider : Class Name : "
                            + providerClass);
                }

            } catch (ClassNotFoundException e) {
                handleException("A Secret Provider cannot be found for class name : " + providerClass);
            } catch (IllegalAccessException e) {
                handleException("Error creating a instance from class : " + providerClass);
            } catch (InstantiationException e) {
                handleException("Error creating a instance from class : " + providerClass);
            }
        }

        initialized = true;
    }

    /**
     * Returns the secret corresponding to the given alias name
     *
     * @param alias The logical or alias name
     * @return If there is a secret , otherwise , alias itself
     */
    public String getSecret(String provider,String repository,String alias) {
        if (Arrays.stream(providerTypesArr).anyMatch(provider::equals)) {
            if (allExternalRepositories.containsKey(repository)){
                return allExternalRepositories.get(repository).getSecret(alias);

            }else if(provider.equals("file")) {
                if (!initialized || parentRepository == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("There is no secret repository. Returning alias itself");
                    }
                    return alias;
                }
                return parentRepository.getSecret(alias);
            } else if (log.isDebugEnabled()){
                log.debug("No such repository can be identified");
            }
        } else if (log.isDebugEnabled()){
            log.debug("No such secret repository provider listed under configurations" );
        }
        return null;
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
