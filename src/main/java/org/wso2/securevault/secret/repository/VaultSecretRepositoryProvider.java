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

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

public class VaultSecretRepositoryProvider implements SecretRepositoryProvider {
    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
        return null;
    }

//    @Override
//    public SecretRepository getVaultRepository(String vaultRepository, IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
//
//        if(vaultRepository.equals("vault1")){
//            return new Vault1SecretRepository(identity, trust);
//        } else{
//            return new Vault2SecretRepository(identity, trust);
//        }
//    }
}
