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
 * software distributed under the License is distributed on anh
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.securevault.secret.repository;


import org.wso2.carbon.securevault.hashicorp.repository.HashiCorpSecretRepository;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

public class VaultSecretRepositoryProvider implements SecretRepositoryProvider {

    SecretRepository vaultRepository;
    ArrayList<SecretRepository> vaultRepositoryArray = new ArrayList<>();
    HashMap<String,SecretRepository> vaultRepositoryMap = new HashMap<>();

    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
        return null;
    }

    @Override
    public HashMap<String, SecretRepository> initProvider(String[] externalRepositories,
                                                          Properties configurationProperties,
                                                          String key,
                                                          IdentityKeyStoreWrapper identity,
                                                          TrustKeyStoreWrapper trust) {

        Properties repositoryProperties;
        for (String externalRepo : externalRepositories){
            repositoryProperties = filterConfigurations(configurationProperties,key,externalRepo);
//            (new Vault2SecretRepository(identity, trust)).init(repositoryProperties);
//            vaultRepositoryArrayItem = getSecretRepository(identity, trust);
            vaultRepository = getVaultRepository(externalRepo,identity, trust);
            vaultRepository.init(repositoryProperties,key);
            vaultRepositoryMap.put(externalRepo,vaultRepository);
        }
        return vaultRepositoryMap;
    }

    @Override
    public Properties filterConfigurations(Properties properties, String provider, String repository) {
        String propertyString = "secretRepositories."+provider+"."+repository;
        new Properties();
        Properties filteredProps;
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
    public SecretRepository getVaultRepository(String vaultRepository, IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {

        switch (vaultRepository){
            case "vault1":
                return new Vault1SecretRepository(identity, trust);
            case "vault2":
                return new Vault2SecretRepository(identity, trust);
            case "hashicorp":
                return new HashiCorpSecretRepository(identity, trust);
            default:
                return null;
        }
    }
}
