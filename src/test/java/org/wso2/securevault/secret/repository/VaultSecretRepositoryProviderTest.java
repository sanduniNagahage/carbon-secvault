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

import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.Map;
import java.util.Properties;

public class VaultSecretRepositoryProviderTest {

    private VaultSecretRepositoryProvider vaultSecretRepositoryProvider;

    @BeforeClass
    public void setUp() {

        vaultSecretRepositoryProvider = new VaultSecretRepositoryProvider();
    }

    @Test(description = "Test case for filterConfigurations() method.")
    public void testFilterConfigurations() throws Exception {

        Properties actual = Whitebox.invokeMethod(vaultSecretRepositoryProvider, "filterConfigurations",
                getConfigProperties(), "hashicorp");
        Assert.assertEquals(4, actual.size());
    }

    @Test(description = "Negative test case for filterConfigurations() method.")
    public void testFilterConfigurationsNegative() throws Exception {

        Properties actual = Whitebox.invokeMethod(vaultSecretRepositoryProvider, "filterConfigurations",
                getConfigProperties(), "aws");
        Assert.assertEquals(0, actual.size());
    }

    @Test(description = "Test case for isPropValueValidated() method.")
    public void testIsPropValueValidated() throws Exception {

        Properties configProps = getConfigProperties();
        for (Map.Entry<Object, Object> entry : configProps.entrySet()) {
            Boolean actual =
                    Whitebox.invokeMethod(vaultSecretRepositoryProvider, "isPropValueValidated", entry.getValue());
            Assert.assertTrue(actual);
        }
    }

    @Test(description = "Test case for getPropertiesFromSecretConfigurations() method.")
    public void testGetPropertiesFromSecretConfigurations() throws Exception {

        for (Map.Entry<Object, Object> entry : getConfigProperties().entrySet()) {
            String actual =
                    Whitebox.invokeMethod(vaultSecretRepositoryProvider, "getPropertiesFromSecretConfigurations",
                            getConfigProperties(), entry.getKey().toString());
            Assert.assertEquals(entry.getValue(), actual);
        }
    }

    private Properties getConfigProperties() {

        Properties configProperties = new Properties();
        configProperties
                .setProperty("secretRepositories.file.location", "repository/conf/security/cipher-text.properties");

        configProperties.setProperty("secretProviders", "vault");

        configProperties.setProperty("secretProviders.vault.provider",
                "org.wso2.securevault.provider.VaultSecretRepositoryProvider");

        configProperties.setProperty("secretProviders.vault.repositories", "hashicorp,samplerepository1");

        configProperties.setProperty("secretProviders.vault.repositories.hashicorp",
                "org.wso2.carbon.securevault.hashicorp.repository.HashiCorpSecretRepository");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1",
                "org.wso2.carbon.securevault.repository.SampleRepository1");

        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.1",
                "samplerepository1prop1");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.2",
                "samplerepository1prop2");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.3",
                "samplerepository1prop3");

        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.address",
                "http://127.0.0.1:8200");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.namespace", "wso2is");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.path.prefix", "wso2is");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.engineVersion", "2");

        return configProperties;
    }
}
