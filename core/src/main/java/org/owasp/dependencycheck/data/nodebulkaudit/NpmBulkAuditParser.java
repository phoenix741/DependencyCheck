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

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.dependencycheck.data.nodeaudit.Advisory;
import org.owasp.dependencycheck.dependency.CvssV3;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONException;

/**
 * Parser for NPM Audit API response. This parser is derived from:
 * https://github.com/DependencyTrack/dependency-track/blob/master/src/main/java/org/owasp/dependencytrack/parser/npm/audit/NpmAuditParser.java
 *
 * @author Steve Springett
 */
public class NpmBulkAuditParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NpmBulkAuditParser.class);

    /**
     * Parses the JSON response from the NPM Audit API.
     *
     * @param jsonResponse the JSON node to parse
     * @return an AdvisoryResults object
     * @throws org.json.JSONException thrown if the JSON is not of the expected
     *                                schema
     */
    public List<Advisory> parse(JSONObject jsonResponse) throws JSONException {
        LOGGER.debug("Parsing JSON node");
        final List<Advisory> advisories = new ArrayList<>();

        final Iterator<?> keys = jsonResponse.keys();
        while (keys.hasNext()) {
            final String key = (String) keys.next();
            final Advisory advisory = parseAdvisory(key, jsonResponse.getJSONObject(key));
            advisories.add(advisory);
        }
        return advisories;
    }

    /**
     * Parses the advisory from Node Audit.
     *
     * @param object the JSON object containing the advisory
     * @return the Advisory object
     * @throws org.json.JSONException thrown if the JSON is not of the expected
     *                                schema
     */
    private Advisory parseAdvisory(String moduleName, JSONObject object) throws JSONException {
        final Advisory advisory = new Advisory();
        advisory.setTitle(object.optString("title", null));
        advisory.setModuleName(moduleName);
        advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
        advisory.setSeverity(object.optString("severity", null));

        final JSONArray jsonCwes = object.optJSONArray("cwe");
        final List<String> stringCwes = new ArrayList<>();
        if (jsonCwes != null) {
            for (int j = 0; j < jsonCwes.length(); j++) {
                stringCwes.add(jsonCwes.getString(j));
            }
        }
        advisory.setCwes(stringCwes);

        final JSONObject jsonCvss = object.optJSONObject("cvss");
        if (jsonCvss != null) {
            float baseScore = -1.0f;
            final String score = jsonCvss.optString("score");
            if (score != null) {
                try {
                    baseScore = Float.parseFloat(score);
                } catch (NumberFormatException ignored) {
                    LOGGER.trace("Swallowed NumberFormatException", ignored);
                    baseScore = -1.0f;
                }
            }
            if (baseScore >= 0.0) {
                final String vector = jsonCvss.optString("vectorString");
                if (vector != null) {
                    if (vector.startsWith("CVSS:3") && baseScore >= 0.0) {
                        try {
                            final CvssV3 cvss = new CvssV3(vector, baseScore);
                            advisory.setCvssV3(cvss);
                        } catch (IllegalArgumentException iae) {
                            LOGGER.warn("Invalid CVSS vector format encountered in NPM Audit results '{}' ", vector,
                                    iae);
                        }
                    } else {
                        LOGGER.warn("Unsupported CVSS vector format in NPM Audit results, please file a feature "
                                + "request at https://github.com/jeremylong/DependencyCheck/issues/new/choose to "
                                + "support vector format '{}' ", vector);
                    }
                }
            }
        }

        return advisory;
    }
}
