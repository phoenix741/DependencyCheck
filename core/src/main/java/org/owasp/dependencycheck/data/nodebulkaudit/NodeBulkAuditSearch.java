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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodebulkaudit;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;
import javax.annotation.concurrent.ThreadSafe;
import javax.json.JsonObject;

import org.apache.commons.collections4.MultiValuedMap;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.dependencycheck.utils.Settings;

import org.owasp.dependencycheck.analyzer.exception.SearchException;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.data.nodeaudit.NodeAuditSearch;

/**
 * Class of methods to search via Node Audit API.
 *
 * @author Steve Springett
 */
@ThreadSafe
public class NodeBulkAuditSearch extends NodeAuditSearch {
    public static final String DEFAULT_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";

    /**
     * Creates a NodeBulkAuditSearch for the given repository URL.
     *
     * @param settings the configured settings
     * @throws java.net.MalformedURLException thrown if the configured URL is
     *                                        invalid
     */
    public NodeBulkAuditSearch(Settings settings) throws MalformedURLException {
        super(settings, settings.getString(Settings.KEYS.ANALYZER_NODE_BULK_AUDIT_URL, DEFAULT_URL));
    }

    /**
     * Parses the response from the Node Audit API.
     * 
     * @param jsonResponse The response from the Node Audit API
     * @return a List of zero or more Advisory object
     * @throws JSONException thrown if there is an error parsing the JSON
     */
    protected List<Advisory> parseResponse(final JSONObject jsonResponse) throws JSONException {
        final NpmBulkAuditParser parser = new NpmBulkAuditParser();
        return parser.parse(jsonResponse);
    }

    /**
     * Construct payload and submit package to Node Audit API.
     * 
     * @param packageJson         a raw package-lock.json file
     * @param dependencyMap       a collection of module/version pairs that is
     * @param skipDevDependencies whether devDependencies should be skipped
     *                            populated while building the payload
     * @return a List of zero or more Advisory object
     * @throws SearchException if Node Audit API is unable to analyze the
     *                         package
     * @throws IOException     if it's unable to connect to Node Audit API
     */
    public List<Advisory> submitPackage(JsonObject lockJson, JsonObject packageJson,
            MultiValuedMap<String, String> dependencyMap, boolean skipDevDependencies)
            throws SearchException, IOException {
        final JsonObject payload = NodeBulkAuditPayloadBuilder.build(lockJson, dependencyMap,
                skipDevDependencies);
        return super.submitPackage(payload);
    }

    /**
     * Construct payload and submit package to Node Audit API.
     * 
     * @param packageJson         a raw package-lock.json file
     * @param dependencyMap       a collection of module/version pairs that is
     * @param skipDevDependencies whether devDependencies should be skipped
     *                            populated while building the payload
     * 
     * @return a List of zero or more Advisory object
     * @throws SearchException if Node Audit API is unable to analyze the
     *                         package
     * @throws IOException     if it's unable to connect to Node Audit API
     */
    public List<Advisory> submitPackage(JsonObject packageJson, MultiValuedMap<String, String> dependencyMap,
            final boolean skipDevDependencies) throws SearchException, IOException {
        final JsonObject payload = NodeBulkAuditPayloadBuilder.build(packageJson, dependencyMap, skipDevDependencies);
        return super.submitPackage(payload);
    }
}
