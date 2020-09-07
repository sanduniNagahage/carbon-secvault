/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *   * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.securevault.secret;

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.repository.Vault1SecretRepository;
import org.wso2.securevault.secret.repository.Vault2SecretRepository;

import java.util.ArrayList;
import java.util.Properties;

/**
 * Factory method for creating a instance of a SecretRepository
 */
public interface SecretRepositoryProvider {

    /**
     * Returns a SecretRepository implementation
     *
     * @param identity Identity KeyStore
     * @param trust    Trust KeyStore
     * @return A SecretRepository implementation
     */
    SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust);

    /**
     * Returns a List of initialized SecretRepositories
     *
     * @param externalRepositories    Repositories other than the file base
     * @param configurationProperties Properties from secret configurations file
     * @param key                     Provider type
     * @param identity                Identity KeyStore
     * @param trust                   Trust KeyStore
     * @return A List of initialized SecretRepositories
     */
    default ArrayList<SecretRepository> initProvider(String[] externalRepositories,
                                                     Properties configurationProperties,
                                                     String key,
                                                     IdentityKeyStoreWrapper identity,
                                                     TrustKeyStoreWrapper trust){ return null; }

    /**
     * Filter properties based on the provider and the repository
     * @param properties Properties from secret configurations file
     * @param provider   Provider string
     * @param repository Repository string
     * @return filtered set of properties
     */
    default Properties filterConfigurations(Properties properties, String provider, String repository){
        String propertyString = "secretRepositories."+provider+".properties"+repository;
        Properties filteredProps = new Properties();
        filteredProps = (Properties) properties.clone();
        Properties finalFilteredProps = filteredProps;
        properties.forEach((k, v) ->{
            if(!(k.toString().contains(propertyString))){
                finalFilteredProps.remove(k);
            }

        });
        return finalFilteredProps;
    }

    /**
     *
     * @param vaultRepository
     * @param identity
     * @param trust Trust KeyStore
     * @return
     */
    default SecretRepository getVaultRepository(String vaultRepository, IdentityKeyStoreWrapper identity,
                                                TrustKeyStoreWrapper trust) { return null; }
}
