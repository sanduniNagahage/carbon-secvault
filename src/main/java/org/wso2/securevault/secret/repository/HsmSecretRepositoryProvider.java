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

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

public class HsmSecretRepositoryProvider implements SecretRepositoryProvider {
    SecretRepository hsmRepositoryArrayItem;
    ArrayList<SecretRepository> hsmRepositoryArray = new ArrayList<>();

    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {

        return null;
    }

    @Override
    public HashMap<String, SecretRepository> initProvider(String[] externalRepositories, Properties configurationProperties,
                                                          String key, IdentityKeyStoreWrapper identity,
                                                          TrustKeyStoreWrapper trust) {
        Properties repositoryProperties;
        for (String externalRepo : externalRepositories){
            switch (externalRepo){
                case "hsm1":
                    repositoryProperties = filterConfigurations(configurationProperties,key,"hsm1");
                    hsmRepositoryArrayItem = getVaultRepository("hsm1",identity, trust);
                    hsmRepositoryArrayItem.init(repositoryProperties);
                    hsmRepositoryArray.add(hsmRepositoryArrayItem);
                    break;
                case  "hsm2":
                    repositoryProperties = filterConfigurations(configurationProperties,key,"hsm2");
//                    (new Vault2SecretRepository(identity, trust)).init(repositoryProperties);
                    hsmRepositoryArrayItem = getVaultRepository("hsm2",identity, trust);
                    hsmRepositoryArrayItem.init(repositoryProperties);
                    hsmRepositoryArray.add(hsmRepositoryArrayItem);
                    break;
            }
        }
        return null;
    }

    @Override
    public Properties filterConfigurations(Properties properties, String provider, String repository) {
        String propertyString = "secretRepositories."+provider+".properties."+repository;
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

    @Override
    public SecretRepository getVaultRepository(String vaultRepository, IdentityKeyStoreWrapper identity,
                                               TrustKeyStoreWrapper trust) {
        switch (vaultRepository){
            case "hsm1":
                return new HSM1(identity, trust);
            case "hsm2":
                return new HSM2(identity, trust);
            default:
                return null;
        }
    }
}
