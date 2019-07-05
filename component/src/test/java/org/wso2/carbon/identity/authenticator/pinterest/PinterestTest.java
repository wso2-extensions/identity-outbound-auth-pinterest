/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.identity.authenticator.pinterest;

import static org.mockito.Matchers.anyString;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.MockitoAnnotations.initMocks;

import org.wso2.carbon.identity.application.common.model.ClaimMapping;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, OAuthClientRequest.class})
public class PinterestTest extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private PinterestAuthenticator pinterestAuthenticator;
    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private HttpServletResponse httpServletResponse;
    @Mock
    private Map<String, String> authenticatorProperties;
    @Mock
    private OAuthClientResponse oAuthClientResponse;
    @Mock
    private AuthenticationContext authenticationContext;
    @Mock
    private OAuthAuthzResponse authAuthzResponse;
    @Mock
    private OAuthClient oAuthClient;
    @Mock
    private BufferedReader bufferedReader;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse = new OAuthJSONAccessTokenResponse();
    private Map<ClaimMapping, String> map = new HashMap<>();

    @Spy
    private AuthenticationContext context = new AuthenticationContext();

    @DataProvider
    public Object[][] getAuthenticatorPropertiesData() {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        return new Object[][]{{authenticatorProperties}};
    }

    @BeforeMethod
    public void setUp() {
        pinterestAuthenticator = new PinterestAuthenticator();
        initMocks(this);
    }

    @Test(description = "Test case for GetName")
    public void testGetName() {
        String name = pinterestAuthenticator.getName();
        Assert.assertEquals("Pinterest", name);
    }

    @Test(description = "Test case for GetConfigurationProperties")
    public void testGetConfigurationProperties() {
        Assert.assertEquals(PinterestAuthenticatorConstants.CALLBACK_URL,
                pinterestAuthenticator.getConfigurationProperties().get(2).getName());
    }

    @Test(description = "Test case for GetFriendlyName")
    public void testGetFriendlyName() {
        Assert.assertEquals(PinterestAuthenticatorConstants.PINTEREST_CONNECTOR_FRIENDLY_NAME,
                pinterestAuthenticator.getFriendlyName());
    }

    @Test(description = "Test case for CanHandle")
    public void testCanHandle() {
        Assert.assertNotNull(pinterestAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for GetAuthorizationServerEndpoint")
    public void testGetAuthorizationServerEndpoint() {
        Assert.assertEquals(PinterestAuthenticatorConstants.PINTEREST_OAUTH_ENDPOINT,
                pinterestAuthenticator.getAuthorizationServerEndpoint(authenticatorProperties));
    }

    @Test(description = "Test case for GetTokenEndpoint")
    public void testGetTokenEndpoint() {
        Assert.assertEquals(PinterestAuthenticatorConstants.PINTEREST_TOKEN_ENDPOINT,
                pinterestAuthenticator.getTokenEndpoint(authenticatorProperties));
    }

    @Test(description = "Test case for GetUserInfoEndpoint")
    public void testGetUserInfoEndpoint() {
        Assert.assertEquals(PinterestAuthenticatorConstants.PINTEREST_USERINFO_ENDPOINT,
                pinterestAuthenticator.getUserInfoEndpoint(oAuthClientResponse, authenticatorProperties));
    }

    @Test(description = "Test case for GetClaimDialectURI")
    public void testGetClaimDialectURI() throws Exception {
        Whitebox.invokeMethod(pinterestAuthenticator, "associateSubjectFromClaims", context,
                "dummy-claim", map);
        Assert.assertEquals(PinterestAuthenticatorConstants.CLAIM_DIALECT_URI,
                pinterestAuthenticator.getClaimDialectURI());
    }

    @Test(description = "Test case for RequiredIDToken")
    public void testRequiredIDToken() throws AuthenticationFailedException {
        pinterestAuthenticator.
                initiateAuthenticationRequest(httpServletRequest, httpServletResponse, authenticationContext);
        Assert.assertEquals(false, pinterestAuthenticator.requiredIDToken(authenticatorProperties));
    }

    @Mock
    private OAuthAuthzResponse mockOAuthAuthzResponse;
    @Test(expectedExceptions = AuthenticationFailedException.class,
            description = "Negative Test case for processAuthenticationResponse",
            dataProvider = "getAuthenticatorPropertiesData")
    public void testProcessAuthenticationResponse(Map<String, String> authenticatorProperties) throws Exception {
        PinterestAuthenticator spyAuthenticator = PowerMockito.spy(new PinterestAuthenticator());
        PowerMockito.when(httpServletRequest.getParameter(anyString())).thenReturn("method");
        context.setAuthenticatorProperties(authenticatorProperties);
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class))).
                thenReturn(authAuthzResponse);
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString())).thenReturn(new OAuthClientRequest.
                TokenRequestBuilder("https://api.pinterest.com/v1/oauth/token"));
        PowerMockito.whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        Mockito.when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        Mockito.when(oAuthClient.accessToken(Mockito.any(OAuthClientRequest.class))).
                thenReturn(oAuthJSONAccessTokenResponse);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = InvalidCredentialsException.class, description = "Negative test case for HandleErrorResponse")
    public void testHandleErrorResponse() throws Exception {
        Whitebox.invokeMethod(pinterestAuthenticator, "handleErrorResponse", httpServletRequest);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class, description = "Negative test case for BuildClaims")
    public void testBuildClaims() throws Exception {
        URL url = PowerMockito.mock(URL.class);
        PowerMockito.whenNew(URL.class).withAnyArguments().thenReturn(url);
        HttpURLConnection httpURLConnection = Mockito.mock(HttpURLConnection.class);
        Mockito.when(url.openConnection()).thenReturn(httpURLConnection);
        String payload = "[{\"sub\":\"admin\"}]";
        ByteArrayInputStream byteInputStream = new ByteArrayInputStream(payload.getBytes(
                StandardCharsets.UTF_8));
        Mockito.when(httpURLConnection.getInputStream()).thenReturn(byteInputStream);
        PowerMockito.whenNew(BufferedReader.class).withAnyArguments().thenReturn(bufferedReader);
        Whitebox.invokeMethod(pinterestAuthenticator, "buildClaims", oAuthClientResponse, map);
    }

    @Test(description = "test case for GetCallbackUrl")
    public void testGetCallbackUrl() {
        Assert.assertNull(pinterestAuthenticator.getCallbackUrl(authenticatorProperties));
    }
}
