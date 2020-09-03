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

import java.util.Properties;

public class Vault1SecretRepository implements SecretRepository {
    private IdentityKeyStoreWrapper identity;
    private TrustKeyStoreWrapper trust;
    String admin_password ;
    String user_store_password ;
    String identity_db_password ;
    String shared_db_password ;
    String keystore_password ;

    public Vault1SecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
        this.identity = identity;
        this.trust = trust;
    }

    @Override
    public void init(Properties properties, String id) {
        admin_password = "admin";
        user_store_password = "admin";
        identity_db_password = "wso2carbon";
        shared_db_password = "wso2carbon";
        keystore_password = "wso2carbon";
    }

    @Override
    public String getSecret(String alias) {
        switch(alias){
            case "admin_password":
                return admin_password;
            case "user_store_password":
                return user_store_password;
            case "identity_db_password":
                return identity_db_password;
            case "shared_db_password":
                return shared_db_password;
            case "keystore_password":
                return keystore_password;
            default:
                return alias;
        }
    }

    @Override
    public String getEncryptedData(String alias) {

        return null;
    }

    @Override
    public void setParent(SecretRepository parent) {

    }

    @Override
    public SecretRepository getParent() {

        return null;
    }
}
