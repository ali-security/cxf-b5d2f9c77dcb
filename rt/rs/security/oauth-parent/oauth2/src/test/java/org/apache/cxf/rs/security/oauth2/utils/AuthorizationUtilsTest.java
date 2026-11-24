/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.rs.security.oauth2.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.apache.cxf.jaxrs.ext.MessageContextImpl;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.junit.Assert;
import org.junit.Test;

public class AuthorizationUtilsTest extends Assert {
    
    @Test
    public void testThrowAuthorizationFailureSingleChallenge() {
        try {
            AuthorizationUtils.throwAuthorizationFailure(Collections.singleton("Basic"));
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            Response r = ex.getResponse();
            assertEquals(401, r.getStatus());
            Object value = r.getMetadata().getFirst(HttpHeaders.WWW_AUTHENTICATE);
            assertNotNull(value);
            assertEquals("Basic", value.toString());
        }
    }
    
    @Test
    public void testThrowAuthorizationFailureManyChallenges() {
        Set<String> challenges = new LinkedHashSet<String>();
        challenges.add("Basic");
        challenges.add("Bearer");
        try {
            AuthorizationUtils.throwAuthorizationFailure(challenges);
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            Response r = ex.getResponse();
            assertEquals(401, r.getStatus());
            Object value = r.getMetadata().getFirst(HttpHeaders.WWW_AUTHENTICATE);
            assertNotNull(value);
            assertEquals("Basic,Bearer", value.toString());
        }
    }

    @Test
    public void testThrowAuthorizationFailureNoChallenge() {
        try {
            AuthorizationUtils.throwAuthorizationFailure(Collections.<String>emptySet());
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            Response r = ex.getResponse();
            assertEquals(401, r.getStatus());
            Object value = r.getMetadata().getFirst(HttpHeaders.WWW_AUTHENTICATE);
            assertNull(value);
        }
    }

    @Test
    public void testThrowAuthorizationFailureWithRealm() {
        try {
            AuthorizationUtils.throwAuthorizationFailure(Collections.singleton("Basic"), "oauth");
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            Response r = ex.getResponse();
            assertEquals(401, r.getStatus());
            Object value = r.getMetadata().getFirst(HttpHeaders.WWW_AUTHENTICATE);
            assertNotNull(value);
            assertEquals("Basic realm=\"oauth\"", value.toString());
        }
    }

    @Test
    public void testThrowAuthorizationFailureWithRealmInvalidCharacters() {
        String realm = "oauth\r\n\r\n\r\nX-Injected: true";
        try {
            AuthorizationUtils.throwAuthorizationFailure(Collections.singleton("Basic"), realm);
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            Response r = ex.getResponse();
            assertEquals(401, r.getStatus());
            Object value = r.getMetadata().getFirst(HttpHeaders.WWW_AUTHENTICATE);
            assertNotNull(value);
            assertEquals("Basic realm=\"oauth______X-Injected: true\"", value.toString());
        }
    }

    @Test
    public void testGetAuthorizationPartsWithMultipleHeadersFails() {
        Message m = new MessageImpl();
        m.put(Message.PROTOCOL_HEADERS, Collections.singletonMap(HttpHeaders.AUTHORIZATION,
                Arrays.asList("Basic YWxpY2U6c2VjcmV0", "Bearer token")));
        MessageContext mc = new MessageContextImpl(m);

        try {
            AuthorizationUtils.getAuthorizationParts(mc);
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            assertEquals(401, ex.getResponse().getStatus());
        }
    }

    @Test
    public void testGetBasicAuthParts() {
        String basicAuthData = Base64Utility.encode("alice:secret".getBytes());

        String[] parts = AuthorizationUtils.getBasicAuthParts(basicAuthData);
        assertArrayEquals(new String[] {"alice", "secret"}, parts);
    }

    @Test
    public void testGetBasicAuthPartsInvalidBase64() {
        try {
            AuthorizationUtils.getBasicAuthParts("not-base64");
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            assertEquals(401, ex.getResponse().getStatus());
        }
    }

    @Test
    public void testGetBasicAuthPartsMissingSeparator() {
        String basicAuthData = Base64Utility.encode("alice".getBytes());

        try {
            AuthorizationUtils.getBasicAuthParts(basicAuthData);
            fail("WebApplicationException expected");
        } catch (WebApplicationException ex) {
            assertEquals(401, ex.getResponse().getStatus());
        }
    }
}
