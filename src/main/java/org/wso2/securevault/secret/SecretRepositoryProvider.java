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
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust);

    default public SecretRepository[] initProvider(String[] externalRepositories, Properties configurationProperties,
                                                   String key,
                                                   IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust){
        filterConfigurations(configurationProperties,key);
        for (String externalRepo : externalRepositories){
            switch (externalRepo){
                case "vault1":
//                    (new Vault1SecretRepository(identity, trust)).init();
                    break;
                case  "vault2":
                    Vault2SecretRepository vault2 = new Vault2SecretRepository(identity,trust);
                    break;
            }
        }
        return new SecretRepository[0];
    }

    default public void filterConfigurations(Properties properties, String key){

    }

//    default public SecretRepository getVaultRepository(String vaultRepository,IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
//
//        if(vaultRepository == "vault1"){
//            return new Vault1SecretRepository(identity, trust);
//        } else{
//            return new Vault2SecretRepository(identity, trust);
//        }
//    }
}
