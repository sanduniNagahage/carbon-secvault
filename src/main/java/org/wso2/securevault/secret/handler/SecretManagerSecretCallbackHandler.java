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
package org.wso2.securevault.secret.handler;

import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SecretManager;
import org.wso2.securevault.secret.SingleSecretCallback;

/**
 * SecretManager based secret provider , this can be used by other application
 * to get secret form  SecretManager
 */
public class SecretManagerSecretCallbackHandler extends AbstractSecretCallbackHandler {

    private final SecretManager secretManager = SecretManager.getInstance();
    private final static String DELIMITER = ":";
    private final static String PROVIDER_FILE = "file";
    private final static String REPOSITORY_FILEBASE = "filebase";

    protected void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {
        String alias;
        String provider = null;
        String repository = null;

        if (!secretManager.isInitialized()) {
            if (log.isWarnEnabled()) {
                log.warn("SecretManager has not been initialized.Cannot collect secrets.");
            }
            return;
        }

        String secretAnnotation = singleSecretCallback.getId();
        String[] parts = secretAnnotation.split(DELIMITER);
        if (parts.length ==1){
            provider = PROVIDER_FILE;
            repository =REPOSITORY_FILEBASE ;
            alias = secretAnnotation;
        }else {
            provider = parts[0];
            repository = parts[1];
            alias = parts[2];
        }

        if (secretAnnotation != null && !"".equals(secretAnnotation)) {
            singleSecretCallback.setSecret(secretManager.getSecret(provider,repository,alias));
        }
    }
}
