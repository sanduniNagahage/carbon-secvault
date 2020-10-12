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
package org.wso2.securevault.secret.provider;


import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;
import java.util.ServiceLoader;

public class VaultSecretRepositoryProvider implements SecretRepositoryProvider {

    SecretRepository vaultRepository;
    ArrayList<SecretRepository> vaultRepositoryArray = new ArrayList<>();
    HashMap<String,SecretRepository> vaultRepositoryMap = new HashMap<>();

    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
        return null;
    }

    @Override
    public HashMap<String, SecretRepository> initProvider(String[] externalRepositoriesArr,
                                                          Properties configurationProperties, String providerType) {
        Properties repositoryProperties;
        ServiceLoader<SecretRepository> loader = ServiceLoader.load(SecretRepository.class);
        Iterator<SecretRepository> iterator = loader.iterator();

        while(iterator.hasNext()){
            vaultRepository = iterator.next();
            String repoType = vaultRepository.getType();
            if (Arrays.stream(externalRepositoriesArr).anyMatch(repoType::equals)){
                repositoryProperties = filterConfigurations(configurationProperties,providerType,repoType);
                vaultRepository.init(repositoryProperties,providerType);
                vaultRepositoryMap.put(vaultRepository.getType(),vaultRepository);
            }
        }
        return vaultRepositoryMap;
    }

    @Override
    public Properties filterConfigurations(Properties properties, String provider, String repository) {
        String propertyString = "secretRepositories."+provider+"."+repository;
        new Properties();
        Properties filteredProps;
        filteredProps = (Properties) properties.clone();
        properties.forEach((k, v) ->{
            if(!(k.toString().contains(propertyString))){
                filteredProps.remove(k);
            }
        });
        return filteredProps;
    }
}
