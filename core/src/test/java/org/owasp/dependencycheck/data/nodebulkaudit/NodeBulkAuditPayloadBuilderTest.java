/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2017 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodebulkaudit;

import java.io.InputStream;

import org.junit.Assert;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import org.owasp.dependencycheck.BaseTest;

public class NodeBulkAuditPayloadBuilderTest {
    @Test
    public void testSanitizePackage() {
        InputStream in = BaseTest.getResourceAsStream(this, "nodejs/package-lock.json");
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        try (JsonReader jsonReader = Json.createReader(in)) {
            JsonObject packageJson = jsonReader.readObject();
            JsonObject sanitized = NodeBulkAuditPayloadBuilder.build(packageJson, dependencyMap, false);

            Assert.assertEquals(85, sanitized.keySet().size());
            for(String key : sanitized.keySet()) {
                if ("kind-of".equals(key)) {
                    Assert.assertEquals(key, 3, sanitized.getJsonArray(key).size());
                } else if ("ms".equals(key)) {
                    Assert.assertEquals(key, 2, sanitized.getJsonArray(key).size());
                } else if ("expand-range".equals("key")) {
                    Assert.assertEquals(key, 1, sanitized.getJsonArray(key).size());
                }
            }
        }
    }

    @Test
    public void testSanitizeV2Package() {
        InputStream in = BaseTest.getResourceAsStream(this, "nodejs/test_lockv2/package-lock.json");
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        try (JsonReader jsonReader = Json.createReader(in)) {
            JsonObject packageJson = jsonReader.readObject();
            JsonObject sanitized = NodeBulkAuditPayloadBuilder.build(packageJson, dependencyMap, false);

            Assert.assertEquals("{\"isobject\":[\"2.1.0\"],\"kind-of\":[\"3.2.2\"],\"is-number\":[\"2.1.0\"],\"isarray\":[\"1.0.0\"],\"is-buffer\":[\"1.1.6\"]}", sanitized.toString());
        }
    }

    @Test
    public void testSanitizeV3Package() {
        InputStream in = BaseTest.getResourceAsStream(this, "nodejs/test_lockv3/package-lock.json");
        final MultiValuedMap<String, String> dependencyMap = new HashSetValuedHashMap<>();
        try (JsonReader jsonReader = Json.createReader(in)) {
            JsonObject packageJson = jsonReader.readObject();
            JsonObject sanitized = NodeBulkAuditPayloadBuilder.build(packageJson, dependencyMap, false);

            Assert.assertEquals("{\"isobject\":[\"2.1.0\"],\"kind-of\":[\"3.2.2\"],\"is-number\":[\"2.1.0\"],\"isarray\":[\"1.0.0\"],\"is-buffer\":[\"1.1.6\"]}", sanitized.toString());
        }
    }
}
