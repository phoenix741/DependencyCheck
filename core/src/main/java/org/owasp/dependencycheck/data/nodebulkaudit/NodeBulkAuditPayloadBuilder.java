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
 * Copyright (c) 2022 Ulrich Vandenhekke. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodebulkaudit;

import org.owasp.dependencycheck.analyzer.NodePackageAnalyzer;

import java.util.Collection;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.collections4.MultiValuedMap;

/**
 * Class used to create the payload to submit to the NPM Audit API service.
 *
 * @author Steve Springett
 * @author Jeremy Long
 */
@ThreadSafe
public final class NodeBulkAuditPayloadBuilder {
    /**
     * Private constructor for utility class.
     */
    private NodeBulkAuditPayloadBuilder() {
        // empty
    }

    /**
     * Builds an npm audit API payload for the bulk interface.
     *
     * Can be used only on a package-lock file.
     * 
     * @param lockJson            the package-lock.json
     * @param dependencyMap       a collection of module/version pairs that is
     *                            populated while building the payload
     * @param skipDevDependencies whether devDependencies should be skipped
     * @return the npm audit API payload
     */
    public static JsonObject build(JsonObject lockJson,
            MultiValuedMap<String, String> dependencyMap, boolean skipDevDependencies) {
        final int lockJsonVersion = lockJson.containsKey("lockfileVersion") ? lockJson.getInt("lockfileVersion") : 1;
        JsonObject dependencies = lockJson.getJsonObject("dependencies");
        if (lockJsonVersion >= 2) {
            dependencies = lockJson.getJsonObject("packages");
        }

        parse(dependencies, dependencyMap, skipDevDependencies, lockJsonVersion == 1);

        final JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        dependencyMap.keys().forEach(key -> {
            final JsonArrayBuilder array = Json.createArrayBuilder();
            final Collection<String> values = dependencyMap.get(key);
            values.forEach(value -> array.add(value));
            payloadBuilder.add(key, array);
        });

        return payloadBuilder.build();
    }

    private static void parse(JsonObject dependencies, MultiValuedMap<String, String> dependencyMap,
            boolean skipDevDependencies, boolean recursivly) {
        if (dependencies != null) {
            dependencies.forEach((key, value) -> {
                final int indexOfNodeModule = key.lastIndexOf(NodePackageAnalyzer.NODE_MODULES_DIRNAME);
                if (indexOfNodeModule >= 0) {
                    key = key.substring(indexOfNodeModule + NodePackageAnalyzer.NODE_MODULES_DIRNAME.length() + 1);
                }

                final JsonObject dep = ((JsonObject) value);
                final String version = dep.getString("version");
                final boolean isDev = dep.getBoolean("dev", false);
                if (skipDevDependencies && isDev) {
                    return;
                }

                if (recursivly && dep.containsKey("dependencies")) {
                    final JsonObject subdependencies = dep.getJsonObject("dependencies");
                    parse(subdependencies, dependencyMap, skipDevDependencies, recursivly);
                }

                if (NodePackageAnalyzer.shouldSkipDependency(key, version)) {
                    return;
                }
                dependencyMap.put(key, version);
            });
        }
    }
}
