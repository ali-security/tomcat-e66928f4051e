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
package org.apache.tomcat.util.compat;

import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.tomcat.util.res.StringManager;

/**
 * Tests the canonical file name cache support added to fix CVE-2024-56337.
 */
public class TestJreCompat {

    private static final StringManager sm = StringManager.getManager(JreCompat.class);

    private static final String USE_CANON_CACHES_TRUE = "-Dsun.io.useCanonCaches=true";
    private static final String USE_CANON_CACHES_FALSE = "-Dsun.io.useCanonCaches=false";


    private static boolean isJre21() {
        try {
            Class.forName("java.util.SequencedCollection");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }


    /**
     * Java 12 onwards (cache disabled by default) must use the Jre12Compat logic and earlier versions must not.
     */
    @Test
    public void testInstanceSelection() {
        Assume.assumeFalse(JreCompat.isGraalAvailable());
        if (Jre12Compat.isSupported()) {
            Assert.assertTrue(JreCompat.isJre12Available());
            Assert.assertTrue(JreCompat.isJre9Available());
            Assert.assertTrue(JreCompat.getInstance() instanceof Jre12Compat);
        } else {
            Assert.assertFalse(JreCompat.isJre12Available());
            Assert.assertFalse(JreCompat.getInstance() instanceof Jre12Compat);
        }
    }


    /**
     * The canonical file name cache was removed in Java 21 so nothing needs to be (or can be) disabled.
     */
    @Test
    public void testCanonCachesAlwaysDisabledOnJava21() {
        Assume.assumeTrue(isJre21());
        Assert.assertTrue(JreCompat.getInstance().isCanonCachesDisabled());
        Assert.assertTrue(JreCompat.getInstance().disableCanonCaches());
    }


    @Test
    public void testMessagesAreDefined() {
        String[] keys = { "jreCompat.useCanonCaches.failed", "jreCompat.useCanonCaches.init",
                "jreCompat.useCanonCaches.java18", "jreCompat.useCanonCaches.none", "jre12Compat.javaPre12",
                "jre12Compat.javaPre21" };
        for (String key : keys) {
            Assert.assertNotNull(key, sm.getString(key));
        }
    }


    /**
     * Java 8 to 11 enable the cache by default. Unless the command line explicitly disables it, Tomcat has to assume
     * it is enabled - this is the case that makes a web application vulnerable to CVE-2024-56337. Java 12 onwards
     * disable it by default.
     */
    @Test
    public void testDefaultCommandLine() throws Exception {
        doTestCommandLine(Collections.<String> emptyList(), false, true);
    }


    /**
     * The mitigation the start-up scripts apply. Both implementations have to recognise it.
     */
    @Test
    public void testCommandLineDisablesCache() throws Exception {
        doTestCommandLine(Collections.singletonList(USE_CANON_CACHES_FALSE), true, true);
    }


    /**
     * A user explicitly enabling the cache re-introduces the exposure on every Java version that still has the cache.
     */
    @Test
    public void testCommandLineEnablesCache() throws Exception {
        doTestCommandLine(Collections.singletonList(USE_CANON_CACHES_TRUE), false, isJre21());
    }


    /**
     * On Java 8 the cache is enabled by default and the field is not final so disableCanonCaches() must be able to
     * switch it off.
     */
    @Test
    public void testDisableCanonCachesJava8() throws Exception {
        Assume.assumeFalse(JreCompat.isJre9Available());
        String output = TesterCanonCaches.fork(Collections.<String> emptyList(), TesterJreCompatCanonCaches.class,
                "disable");
        assertMarker(output, "FIELD_BEFORE=true");
        assertMarker(output, "DISABLE=true");
        assertMarker(output, "FIELD_AFTER=false");
        assertMarker(output, "DISABLED_AFTER=true");
    }


    private void doTestCommandLine(List<String> jvmArgs, boolean expectedBase, boolean expectedJre12)
            throws Exception {
        String output = TesterCanonCaches.fork(jvmArgs, TesterJreCompatCanonCaches.class);

        Assert.assertTrue("Forked JVM did not complete. Output:\n" + output, output.contains("DONE"));
        assertMarker(output, "BASE_DISABLED=" + expectedBase);
        assertMarker(output, "JRE12_DISABLED=" + expectedJre12);
    }


    private void assertMarker(String output, String marker) {
        Assert.assertTrue("Expected [" + marker + "] in the output of the forked JVM:\n" + output,
                output.contains(marker + System.lineSeparator()) || output.contains(marker + "\n"));
    }
}
