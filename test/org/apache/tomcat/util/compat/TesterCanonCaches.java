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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Helpers for testing the canonical file name cache handling added for CVE-2024-56337.
 * <p>
 * The behaviour under test depends on the command line the JVM was started with and changes global JVM state, so
 * the tests drive a forked JVM and assert on the markers it writes to standard out.
 */
public class TesterCanonCaches {

    private TesterCanonCaches() {
        // Utility class. Hide default constructor.
    }


    /**
     * Simulates a JVM on which Tomcat is unable to obtain a reference to the java.io.FileSystem.useCanonCaches field
     * (security manager, missing module opens, a JVM without the field, etc.).
     */
    public static void preventDisablingCanonCaches() {
        JreCompat.useCanonCachesField = Optional.empty();
    }


    /**
     * Reads the java.io.FileSystem.useCanonCaches field directly.
     *
     * @return The current value of the field or {@code null} if it cannot be read on this JVM
     */
    public static Boolean readUseCanonCaches() {
        try {
            Field f = Class.forName("java.io.FileSystem").getDeclaredField("useCanonCaches");
            f.setAccessible(true);
            return (Boolean) f.get(null);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }


    /**
     * Runs the given class in a forked JVM, using the class path of the current JVM, and returns everything it wrote
     * to standard out and standard error.
     *
     * @param jvmArgs Additional JVM arguments
     * @param main    The class to run
     * @param args    The arguments for the class to run
     *
     * @return The output of the forked JVM
     *
     * @throws IOException          If the JVM could not be started or its output could not be read
     * @throws InterruptedException If the current thread is interrupted while waiting for the JVM
     */
    public static String fork(List<String> jvmArgs, Class<?> main, String... args)
            throws IOException, InterruptedException {

        List<String> command = new ArrayList<>();
        command.add(new File(new File(System.getProperty("java.home"), "bin"), "java").getAbsolutePath());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.addAll(jvmArgs);
        command.add(main.getName());
        for (String arg : args) {
            command.add(arg);
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = p.getInputStream()) {
            byte[] buf = new byte[4096];
            int read = is.read(buf);
            while (read > 0) {
                baos.write(buf, 0, read);
                read = is.read(buf);
            }
        }
        if (!p.waitFor(120, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("Forked JVM did not complete within 120s. Output:\n" + baos.toString("UTF-8"));
        }

        return baos.toString("UTF-8");
    }
}
