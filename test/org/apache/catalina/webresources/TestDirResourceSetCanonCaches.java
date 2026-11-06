/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.webresources;

import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.compat.TesterCanonCaches;
import org.apache.tomcat.util.res.StringManager;

/**
 * Tests the CVE-2024-56337 exposure check added to {@link DirResourceSet#initInternal()}. Each test starts a
 * {@link DirResourceSet} in a forked JVM since the check depends on the JVM command line and changes global JVM state.
 */
public class TestDirResourceSetCanonCaches {

    private static final StringManager sm = StringManager.getManager(DirResourceSet.class);

    private static final String USE_CANON_CACHES_TRUE = "-Dsun.io.useCanonCaches=true";
    private static final String USE_CANON_CACHES_FALSE = "-Dsun.io.useCanonCaches=false";

    /* Fragment of dirResourceSet.canonCaches.disabled */
    private static final String DISABLED_WARNING = "Disabled the global canonical file name cache";
    /* Fragment of dirResourceSet.canonCaches.enabled */
    private static final String EXPOSED_WARNING = "may be exposed to CVE-2024-56337";
    /* jreCompat.useCanonCaches.none - only logged if an attempt was made to disable the cache */
    private static final String DISABLE_ATTEMPTED_WARNING =
            "No reference to the java.io.FileSystem.useCanonCaches static field available";


    @Test
    public void testMessagesAreDefined() {
        Assert.assertNotNull(sm.getString("dirResourceSet.canonCaches.disabled"));
        Assert.assertNotNull(sm.getString("dirResourceSet.canonCaches.enabled"));
    }


    /**
     * The vulnerable default on Java 8 to 11: a writable resource set started without the start-up script mitigation.
     * Tomcat must notice and disable the cache.
     */
    @Test
    public void testCanonCachesDisabledAtStart() throws Exception {
        Assume.assumeFalse("The cache is disabled by default on Java 12 onwards", JreCompat.isJre12Available());
        String output = fork(Collections.<String> emptyList(), "false");

        assertMarker(output, "CANON_CACHES_DISABLED=false");
        Assert.assertTrue("Tomcat did not disable the canonical file name cache:\n" + output,
                output.contains(DISABLED_WARNING));
        Assert.assertFalse(output.contains(EXPOSED_WARNING));
        assertMarker(output, "START=OK");
        if (!JreCompat.isJre9Available()) {
            // Java 8 - the field is accessible so confirm the cache really was disabled
            assertMarker(output, "FIELD_BEFORE=true");
            assertMarker(output, "FIELD_AFTER=false");
        }
    }


    /**
     * The cache cannot be disabled. Upstream refuses to start the resource set. The sealed build warns that the
     * resource set may be exposed and starts it.
     */
    @Test
    public void testCanonCachesCannotBeDisabled() throws Exception {
        String output = fork(Collections.singletonList(USE_CANON_CACHES_TRUE), "false", "prevent");

        Assume.assumeTrue("The cache does not exist on this JVM", output.contains("CANON_CACHES_DISABLED=false"));
        Assert.assertTrue("Tomcat did not try to disable the canonical file name cache:\n" + output,
                output.contains(DISABLE_ATTEMPTED_WARNING));
        Assert.assertTrue("No CVE-2024-56337 exposure warning was logged:\n" + output,
                output.contains("WARN|org.apache.catalina.webresources.DirResourceSet|") &&
                        output.contains(EXPOSED_WARNING));
        assertMarker(output, "START=OK");
    }


    /**
     * The mitigation the start-up scripts apply. No warning, and the cache is never touched.
     */
    @Test
    public void testCanonCachesDisabledOnTheCommandLine() throws Exception {
        String output = fork(Collections.singletonList(USE_CANON_CACHES_FALSE), "false");

        assertMarker(output, "CANON_CACHES_DISABLED=true");
        Assert.assertFalse("A warning was logged for a protected JVM:\n" + output,
                output.contains(DISABLED_WARNING) || output.contains(EXPOSED_WARNING));
        assertMarker(output, "START=OK");
    }


    /**
     * Neither CVE-2024-56337 nor CVE-2024-50379 is exploitable against a read only resource set so the check must
     * not fire - and must not disable the cache - for one.
     */
    @Test
    public void testReadOnlyResourceSetIsNotChecked() throws Exception {
        String output = fork(Collections.singletonList(USE_CANON_CACHES_TRUE), "true");

        Assert.assertFalse("A warning was logged for a read only WebResourceSet:\n" + output,
                output.contains(DISABLED_WARNING) || output.contains(EXPOSED_WARNING) ||
                        output.contains(DISABLE_ATTEMPTED_WARNING));
        assertMarker(output, "START=OK");
        if (!JreCompat.isJre9Available()) {
            assertMarker(output, "FIELD_AFTER=true");
        }
    }


    private String fork(List<String> jvmArgs, String... args) throws Exception {
        String output = TesterCanonCaches.fork(jvmArgs, TesterDirResourceSetCanonCaches.class, args);
        Assert.assertTrue("Forked JVM did not complete. Output:\n" + output, output.contains("DONE"));
        return output;
    }


    private void assertMarker(String output, String marker) {
        Assert.assertTrue("Expected [" + marker + "] in the output of the forked JVM:\n" + output,
                output.contains(marker + System.lineSeparator()) || output.contains(marker + "\n"));
    }
}
