/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2022. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.auth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.HttpException;
import com.hcl.appscan.sdk.http.HttpClient;
import com.hcl.appscan.sdk.http.HttpsClient;
import com.hcl.appscan.sdk.http.HttpResponse;

public class AuthenticationHandler implements CoreConstants {

	private IAuthenticationProvider m_authProvider;
	
	public AuthenticationHandler(IAuthenticationProvider provider) {
		m_authProvider = provider;
	}
	
	/**
	 * Authenticates a user with the HCL AppScan on Cloud service using a username and password.
	 * @param username The username.
	 * @param password The password.
	 * @param persist True to persist the credentials.
	 * @return True if successful.
	 * @throws IOException If an error occurs.
	 * @throws JSONException If an error occurs.
	 */
	public boolean login(String username, String password, boolean persist) throws IOException, JSONException {
		return login(username, password, persist, LoginType.ASoC);
	}
	
	/**
	 * Authenticates a user using the given LoginType.
	 * @param username The username.
	 * @param password The password.
	 * @param persist True to persist the credentials.
	 * @param type The LoginType.
	 * @return True if successful.
	 * @throws IOException If an error occurs.
	 * @throws JSONException If an error occurs.
	 */
	public boolean login(String username, String password, boolean persist, LoginType type) throws IOException, JSONException {
		return login(username, password, persist, type, null);
	}

	/**
	 * Authenticates a user using the given LoginType.
	 * @param username The username.
	 * @param password The password.
	 * @param persist True to persist the credentials.
	 * @param type The LoginType.
	 * @param clientType The client to specify in the ClientType header.
	 * @return True if successful.
	 * @throws IOException If an error occurs.
	 * @throws JSONException If an error occurs.
	 */
	public boolean login(String username, String password, boolean persist, LoginType type, String clientType) throws IOException, JSONException {
		
		Map<String, String> headers = new HashMap<String, String>();
		headers.put(CONTENT_TYPE, "application/x-www-form-urlencoded"); //$NON-NLS-1$
		headers.put(CHARSET, UTF8);
		
		Map<String, String> params = new HashMap<String, String>();
		String url;
		
		if(type == LoginType.ASoC_Federated) {
			params.put(KEY_ID, username);
			params.put(KEY_SECRET, password);
			if(clientType != null) {
				//Only allow letters, numbers, -, _, and . characters.
				clientType = clientType.replaceAll("[^a-zA-Z0-9\\-\\._]", "");
				params.put(CoreConstants.CLIENT_TYPE, clientType);
				headers.put(CoreConstants.CLIENT_TYPE, clientType);
			}
		    url = m_authProvider.getServer() + API_KEY_LOGIN;
		}
		else {
			throw new HttpException(500, Messages.getMessage("error.login.type.deprectated")); //$NON-NLS-1$
		}

		HttpClient client = new HttpClient(m_authProvider.getProxy());
	    HttpResponse response = client.postForm(url, headers, params);
	    
		if(response.getResponseCode() == HttpsURLConnection.HTTP_OK || response.getResponseCode() == HttpsURLConnection.HTTP_CREATED) {
			if(persist) {
				JSONObject object = (JSONObject)response.getResponseBodyAsJSON();
				String token = object.getString(TOKEN);
				m_authProvider.saveConnection(token);
			}
			return true;
		}
		else {
			String reason = response.getResponseBodyAsString() == null ? Messages.getMessage("message.unknown") : response.getResponseBodyAsString(); //$NON-NLS-1$
			throw new HttpException(response.getResponseCode(), reason);
		}
	}
	
	public boolean isTokenExpired() {
		boolean isExpired;
		String request_url = m_authProvider.getServer() + API_APPS_COUNT;
		
		Map<String, String> headers = m_authProvider.getAuthorizationHeader(false);
		headers.put("Accept", "application/json"); //$NON-NLS-1$ //$NON-NLS-2$
		headers.put(CHARSET, UTF8);
        HttpResponse httpResponse;

        if(!(m_authProvider.getServer().endsWith("appscan.com/"))){
            HttpsClient httpClient = new HttpsClient();
            try {
                httpResponse = httpClient.get(request_url, headers, null);
                isExpired = httpResponse.getResponseCode() != HttpsURLConnection.HTTP_OK;
            } catch (IOException e) {
                isExpired = true;
            }
        } else {
            HttpClient httpClient = new HttpClient(m_authProvider.getProxy());
            try {
                httpResponse = httpClient.get(request_url, headers, null);
                isExpired = httpResponse.getResponseCode() != HttpsURLConnection.HTTP_OK;
            } catch (IOException e) {
                isExpired = true;
            }
        }
		return isExpired;
	}
}
