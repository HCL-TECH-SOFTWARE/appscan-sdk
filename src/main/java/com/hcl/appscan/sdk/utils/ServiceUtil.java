/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2020, 2023.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.utils;

import java.io.File;
import java.io.IOException;
import java.net.Proxy;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import com.hcl.appscan.sdk.http.HttpsClient;
import org.apache.wink.json4j.JSONArtifact;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpClient;
import com.hcl.appscan.sdk.http.HttpResponse;

/**
 * Provides scan service utilities.
 */
public class ServiceUtil implements CoreConstants {
	
	/**
	 * Gets the SAClientUtil package used for running static analysis.
	 * 
	 * @param destination The file to save the package to.
	 * @throws IOException If an error occurs.
	 */
	public static void getSAClientUtil(File destination) throws IOException {
		getSAClientUtil(destination, Proxy.NO_PROXY);
	}

        public static void getSAClientUtil(File destination, Proxy proxy) throws IOException {
                getSAClientUtil(destination, Proxy.NO_PROXY, "", "");
        }
	
	/**
	 * Gets the SAClientUtil package used for running static analysis.
	 * 
	 * @param destination The file to save the package to.
	 * @param proxy The proxy for the connection, if required.
	 * @throws IOException If an error occurs.
	 */
	public static void getSAClientUtil(File destination, Proxy proxy, String serverURL, String acceptInvalidCerts) throws IOException {
        String request_url = SystemUtil.getDefaultServer();
        if(serverURL !=null && !serverURL.isEmpty()){
            request_url = serverURL;
        }
        request_url += String.format(API_SACLIENT_DOWNLOAD, API_SCX, SystemUtil.getOS());

        HttpClient client = new HttpClient(proxy,acceptInvalidCerts.equals("true"));
        HttpResponse response = client.get(request_url, null, null);

		if (response.getResponseCode() == HttpsURLConnection.HTTP_OK || response.getResponseCode() == HttpsURLConnection.HTTP_CREATED) {
			if(!destination.getParentFile().isDirectory())
				destination.getParentFile().mkdirs();
			
			response.getResponseBodyAsFile(destination);
		}
		else
			throw new IOException(response.getResponseBodyAsString());
	}
	
	/**
	 * Gets the latest available version of the SAClientUtil package used for running static analysis.
	 * 
	 * @return The current version of the package.
	 * @throws IOException If an error occurs.
	 */
	public static String getSAClientVersion() throws IOException {
		return getSAClientVersion(Proxy.NO_PROXY);
	}

    	public static String getSAClientVersion(Proxy proxy) throws IOException {
        	return getSAClientVersion(proxy, "");
    	}
	
	/**
	 * Gets the latest available version of the SAClientUtil package used for running static analysis.
	 * 
	 * @param proxy The {@link Proxy} to use.
	 * @return The current version of the package.
	 * @throws IOException If an error occurs.
	 */
	public static String getSAClientVersion(Proxy proxy, String serverURL) throws IOException {
        String request_url = SystemUtil.getDefaultServer();
        if(serverURL != null && !serverURL.isEmpty()){
            request_url = serverURL;
        }
        request_url += String.format(API_SACLIENT_VERSION, API_SCX, SystemUtil.getOS(), "true"); 
		
		HttpClient client = new HttpClient(proxy);
		HttpResponse response = client.get(request_url, null, null);
		
		if (response.getResponseCode() == HttpsURLConnection.HTTP_OK || response.getResponseCode() == HttpsURLConnection.HTTP_CREATED) {
			try {
				JSONArtifact responseContent = response.getResponseBodyAsJSON();
				if (responseContent != null) {
					JSONObject object = (JSONObject) responseContent;
					return object.getString(VERSION_NUMBER);
				}
			} catch (JSONException e) {
				return "0"; //$NON-NLS-1$
			}
		}
		return null;
	}
	
	/**
	 * Checks if the given url is valid for scanning.
	 * 
	 * @param url The url to test.
	 * @param provider The IAuthenticationProvider for authentication.
	 * @return True if the url is valid. False is returned if the url is not valid, the request fails, or an exception occurs.
	 */
	public static boolean isValidUrl(String url, IAuthenticationProvider provider) {
		return isValidUrl(url, provider, Proxy.NO_PROXY);
	}
	
	/**
	 * Checks if the given url is valid for scanning.
	 * 
	 * @param url The url to test.
	 * @param provider The IAuthenticationProvider for authentication.
	 * @param proxy The proxy to use for the connection.
	 * @return True if the url is valid. False is returned if the url is not valid, the request fails, or an exception occurs.
	 */
	public static boolean isValidUrl(String url, IAuthenticationProvider provider, Proxy proxy) {
		String request_url = provider.getServer() + API_IS_VALID_URL;

		try {
			JSONObject body = new JSONObject();
			body.put(URL, url);

			HttpClient client = new HttpClient(proxy);
			HttpResponse response = client.post(request_url, provider.getAuthorizationHeader(false), body.toString());

			if (response.isSuccess()) {
				JSONArtifact responseContent = response.getResponseBodyAsJSON();
				if (responseContent != null) {
					JSONObject object = (JSONObject) responseContent;
					return object.getBoolean(IS_VALID);
				}
			}
		} catch (IOException | JSONException e) {
			// Ignore and return false.
		}
		
		return false;
	}
}
