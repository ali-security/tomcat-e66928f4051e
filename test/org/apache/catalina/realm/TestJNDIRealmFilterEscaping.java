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
package org.apache.catalina.realm;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

import javax.naming.NameNotFoundException;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import org.junit.Assert;
import org.junit.Test;

import org.apache.juli.logging.LogFactory;

/*
 * Checks that user and role names are escaped where they are substituted into
 * LDAP search filters and distinguished names (CVE-2021-30640). Upstream
 * covers this with TestJNDIRealmIntegration which needs an embedded LDAP
 * server, so the directory is replaced here by a stub that records the
 * names and filters it receives.
 */
public class TestJNDIRealmFilterEscaping {

    @Test
    public void testUserSearchFilterIsEscaped() throws Exception {
        JNDIRealm realm = createRealm();
        realm.setUserSearch("(uid={0})");
        TesterDirContext ldap = new TesterDirContext();

        Assert.assertNull(realm.getUserBySearch(ldap.proxy(), "*)(uid=*", null));

        Assert.assertEquals(Collections.singletonList("(uid=\\2a\\29\\28uid=\\2a)"), ldap.filters);
    }


    @Test
    public void testUserPatternIsAttributeValueEscaped() throws Exception {
        JNDIRealm realm = createRealm();
        realm.setUserPattern("uid={0},ou=people,dc=example,dc=com");
        TesterDirContext ldap = new TesterDirContext();

        JNDIRealm.User user = realm.getUserByPattern(ldap.proxy(), "t;,x", null, null, 0);

        Assert.assertEquals("uid=t\\3B\\2Cx,ou=people,dc=example,dc=com", user.getDN());
    }


    @Test
    public void testRoleSearchFilterIsEscaped() throws Exception {
        JNDIRealm realm = createRealm();
        realm.setRoleSearch("(|(member={0})(memberUid={1})(roleId={2}))");
        realm.setRoleName("cn");
        TesterDirContext ldap = new TesterDirContext();
        JNDIRealm.User user = new JNDIRealm.User(
                "t;*", "cn=t\\3B\\2A,ou=people,dc=example,dc=com", null, null, "r(1)");

        realm.getRoles(ldap.proxy(), user);

        Assert.assertEquals(Collections.singletonList(
                "(|(member=cn=t\\5c3B\\5c2A,ou=people,dc=example,dc=com)" +
                "(memberUid=t\\5c3B\\2a)(roleId=r\\281\\29))"), ldap.filters);
    }


    @Test
    public void testRoleBaseSubstitutionIsHexEscaped() throws Exception {
        JNDIRealm realm = createRealm();
        realm.setRoleSearch("(member={0})");
        realm.setRoleName("cn");
        realm.setRoleBase("{1},ou=groups,dc=example,dc=com");
        TesterDirContext ldap = new TesterDirContext();
        JNDIRealm.User user = new JNDIRealm.User(
                "t;", "cn=t\\;,ou=people", null, null, null);

        realm.getRoles(ldap.proxy(), user);

        Assert.assertEquals(Collections.singletonList("cn=t\\3B,ou=groups,dc=example,dc=com"),
                ldap.names);
    }


    private static JNDIRealm createRealm() {
        JNDIRealm realm = new JNDIRealm();
        // Normally set when the realm is started
        realm.containerLog = LogFactory.getLog(TestJNDIRealmFilterEscaping.class);
        return realm;
    }


    private static class TesterDirContext implements InvocationHandler {

        private final List<String> names = new ArrayList<>();
        private final List<String> filters = new ArrayList<>();

        DirContext proxy() {
            return (DirContext) Proxy.newProxyInstance(TestJNDIRealmFilterEscaping.class.getClassLoader(),
                    new Class<?>[] { DirContext.class }, this);
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "getAttributes":
                    names.add((String) args[0]);
                    throw new NameNotFoundException();
                case "search":
                    names.add((String) args[0]);
                    filters.add((String) args[1]);
                    return emptyResults();
                case "getNameParser":
                    return (NameParser) LdapName::new;
                case "getEnvironment":
                    return new Hashtable<>();
                default:
                    throw new UnsupportedOperationException(method.toString());
            }
        }

        @SuppressWarnings("unchecked")
        private static NamingEnumeration<SearchResult> emptyResults() {
            return (NamingEnumeration<SearchResult>) Proxy.newProxyInstance(
                    TestJNDIRealmFilterEscaping.class.getClassLoader(),
                    new Class<?>[] { NamingEnumeration.class },
                    (p, m, a) -> "close".equals(m.getName()) ? null : Boolean.FALSE);
        }
    }
}
