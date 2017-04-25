/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

public class PinterestAuthenticatorConstants {

	/*
	 * Private Constructor will prevent the instantiation of this class directly
	 */
	private PinterestAuthenticatorConstants() {
	}

	//Pinterest authorize endpoint URL.
	public static final String PINTEREST_OAUTH_ENDPOINT = "https://api.pinterest.com/oauth/";
	//office365 token  endpoint URL.
	public static final String PINTEREST_TOKEN_ENDPOINT = "https://api.pinterest.com/v1/oauth/token";
	//office365 user info endpoint URL.
	public static final String PINTEREST_USERINFO_ENDPOINT = "https://api.pinterest.com/v1/me";
	//Pinterest connector friendly name.
	public static final String PINTEREST_CONNECTOR_FRIENDLY_NAME = "Pinterest Authenticator";
	//Pinterest connector name.
	public static final String PINTEREST_CONNECTOR_NAME = "Pinterest";
	//The authorization code that the application requested.
	public static final String OAUTH2_GRANT_TYPE_CODE = "code";
	//A randomly generated non-reused value that is sent in the request and returned in the response.
	public static final String OAUTH2_PARAM_STATE = "state";
	//The access token.
	public static final String ACCESS_TOKEN = "access_token";
	//The client ID of the client application.
	public static final String CLIENT_ID = "Client Id";
	//The value of the key that contains the client password.
	public static final String CLIENT_SECRET = "Client Secret";
	//The reply URL of the application.
	public static final String CALLBACK_URL = "callbackUrl";
	//The ID of the user.
	public static final String USER_ID = "id";
	//The claim dialect uri.
	public static final String CLAIM_DIALECT_URI = "http://wso2.org/pinterest/claims";
	//A comma-separated list of permission scopes
	public static final String PINTEREST_BASIC_SCOPE = "read_public,write_public";
	//The Http get method
	public static final String HTTP_GET_METHOD = "GET";
	//Root element of the json response
	public static final String ROOT_ELEMENT = "data";
	//Constant for connection time out
	public static final int CONNECTION_TIMEOUT_VALUE = 15000;
	//Constant for read time out
	public static final int READ_TIMEOUT_VALUE = 15000;
}