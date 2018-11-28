/*
 * Copyright 2018-Present Okta, Inc.
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
 */
package com.okta.jwt.impl.http

import com.okta.jwt.RestoreSystemProperties
import com.okta.jwt.impl.TestUtil
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.testng.annotations.Listeners
import org.testng.annotations.Test

import static org.hamcrest.Matchers.containsString
import static org.hamcrest.Matchers.is
import static org.junit.Assert.assertThat

@Listeners(RestoreSystemProperties.class)
class OkHttpClientTest {

    @Test
    void simpleSuccessTest() {

        def server = new MockWebServer()
        server.enqueue(new MockResponse().setBody("a response body"))
        def url = server.url("/v1/foo").url()
        try {
            def responseStream = new OkHttpClient(20L, 20L).get(url)
            assertThat responseStream.text, is("a response body")
        } finally {
            server.shutdown()
        }
    }

    @Test
    void errorResponseTest() {

        def server = new MockWebServer()
        server.enqueue(new MockResponse().setBody("a response body").setResponseCode(400))
        def url = server.url("/foobar").url()

        try {
            def e = TestUtil.expect(IOException, { new OkHttpClient(20L, 20L).get(url) })
            assertThat e.getMessage(), containsString("400")
            assertThat e.getMessage(), containsString(url.toString())
        } finally {
            server.shutdown()
        }
    }

    @Test()
    void proxyConfigTest() {

        def server = new MockWebServer()
        server.enqueue(new MockResponse().setBody("a response body"))
        def url = server.url("/v1/foo").url()

        System.setProperty("http.proxyHost", url.host)
        System.setProperty("http.proxyPort", url.port.toString())

        try {
            def responseStream = new OkHttpClient(20L, 20L)
                    .get(new URL("http://invalid.example.com:8080/v1/foo"))
            assertThat responseStream.text, is("a response body")
        } finally {
            server.shutdown()
        }
    }
}