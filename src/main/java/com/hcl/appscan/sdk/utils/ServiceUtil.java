/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.utils;

import java.io.File;
import java.io.IOException;
import java.net.Proxy;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import org.apache.wink.json4j.JSONArray;
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
        String request_url = requiredServerURL(serverURL);
        request_url += String.format(API_SACLIENT_DOWNLOAD, SystemUtil.getOS());

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

    private static String requiredServerURL(String serverURL){
        String request_url = SystemUtil.getDefaultServer();
        if(serverURL != null && !serverURL.isEmpty()) {
                request_url = serverURL;
            }
        return request_url;
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
        String request_url = requiredServerURL(serverURL);
        request_url += String.format(API_SACLIENT_VERSION, SystemUtil.getOS(), "true");
		
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

			HttpClient client = new HttpClient(proxy, provider.getacceptInvalidCerts());
			Map<String,String> requestHeaders= provider.getAuthorizationHeader(false);
			requestHeaders.put("Content-Type", "application/json");
			HttpResponse response = client.post(request_url, requestHeaders, body.toString());

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
	
	/**
	 * Checks if the user has entitlement to run SCA scans.
	 * 
	 * @param provider The IAuthenticationProvider for authentication.
	 * @return true if the user has SCA entitlement.
	 */
	public static boolean hasScaEntitlement(IAuthenticationProvider provider) {
		return hasEntitlement(SCA_TECH, provider);
	}
	
	/**
	 * Checks if the user has entitlement to run SAST scans.
	 * 
	 * @param provider The IAuthenticationProvider for authentication.
	 * @return true if the user has SAST entitlement.
	 */
	public static boolean hasSastEntitlement(IAuthenticationProvider provider) {
		return hasEntitlement(STATIC_TECH, provider);
	}
	
	/**
	 * Checks if the user has entitlement to run DAST scans.
	 * 
	 * @param provider The IAuthenticationProvider for authentication.
	 * @return true if the user has DAST entitlement.
	 */
	public static boolean hasDastEntitlement(IAuthenticationProvider provider) {
		return hasEntitlement(DYNAMIC_TECH, provider);
	}

	private static boolean hasEntitlement(String scanType, IAuthenticationProvider provider) {
		if(provider.isTokenExpired()) {
			return true;
		}

		String request_url = provider.getServer() + API_TENANT_INFO;

		try {
			HttpClient client = new HttpClient(provider.getProxy(), provider.getacceptInvalidCerts());
			Map<String,String> requestHeaders= provider.getAuthorizationHeader(false);
			requestHeaders.put("Content-Type", "application/json");
			requestHeaders.put("accept", "application/json");
			HttpResponse response = client.get(request_url, requestHeaders, null);

			if (response.isSuccess()) {
				JSONArtifact responseContent = response.getResponseBodyAsJSON();
				if (responseContent != null) {
					JSONObject object = (JSONObject) responseContent;
					String activeTechnologies = object.getString("ActiveTechnologies");
					return activeTechnologies.contains(scanType);
				}
			}
		} catch (IOException | JSONException e) {
			// Ignore and return false.
		}

		return false;
	}

    /**
     * Checks if the given scanId is valid for scanning.
     *
     * @param scanId The scanId to test.
     * @param applicationId The applicationId to verify.
     * @param type The scanType to verify.
     * @param provider The IAuthenticationProvider for authentication.
     * @return True if the scanId is valid. False is returned if the scanId is not valid, the request fails, or an exception occurs.
     */
    public static boolean isScanId(String scanId, String applicationId, String type, IAuthenticationProvider provider) {
        if (provider.isTokenExpired()) {
            return true;
        }

        String request_url = provider.getServer() + API_BASIC_DETAILS;
        request_url += "?$filter=Id%20eq%20" + scanId + "&%24select=AppId%2C%20Technology";
        Map<String, String> request_headers = provider.getAuthorizationHeader(true);

        HttpClient client = new HttpClient(provider.getProxy(), provider.getacceptInvalidCerts());
        try {
            HttpResponse response = client.get(request_url, request_headers, null);

            if (response.isSuccess()) {
                JSONObject obj = (JSONObject) response.getResponseBodyAsJSON();
                JSONArray array = (JSONArray) obj.get(ITEMS);
                if (array.isEmpty()) {
                    return false;
                } else {
                    JSONObject body = (JSONObject) array.getJSONObject(0);
                    String appId = body.getString(CoreConstants.APP_ID);
                    String technologyName = body.getString("Technology");
                    return appId.equals(applicationId) && technologyName.equals(updatedScanType(type));
                }
            }
        } catch (IOException | JSONException e) {
            // Ignore and return false.
        }

        return false;
    }

    public static String updatedScanType(String type) {
        switch (type) {
            case "Static Analyzer":
                return STATIC_TECH;
            case "Dynamic Analyzer":
                return DYNAMIC_TECH;
            case CoreConstants.SOFTWARE_COMPOSITION_ANALYZER:
                return SCA_TECH;
        }
        return type;
    }

    public static void updateScanData(Map<String, String> params, String scanId, IAuthenticationProvider provider, IProgress progress) {
        if (provider.isTokenExpired()) {
            return;
        }

        String request_url = provider.getServer() + String.format(API_SCANNER,scanId);
        Map<String, String> request_headers = provider.getAuthorizationHeader(true);
        request_headers.put("accept", "application/json");
        request_headers.put("Content-Type", "application/json");

        HttpClient client = new HttpClient(provider.getProxy(), provider.getacceptInvalidCerts());
        try {
            HttpResponse response = client.put(request_url, request_headers, params);
            if (response.getResponseCode() == HttpsURLConnection.HTTP_NO_CONTENT) {
                progress.setStatus(new Message(Message.INFO, Messages.getMessage(UPDATE_JOB)));
            }
        } catch (IOException | JSONException e) {
            progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
        }
    }

    /**
     * Checks if the given scanId is valid for scanning.
     *
     * @param scanId The scanId to test
     * @param provider The IAuthenticationProvider for authentication.
     * @return True if the scanId is valid. False is returned if the scanId is not valid, the request fails, or an exception occurs.
     */
    public static JSONObject sastScanDetails(String scanId, IAuthenticationProvider provider) {
        if (provider.isTokenExpired()) {
            return null;
        }

        String request_url = provider.getServer() + String.format(API_SAST_DETAILS, scanId);
        Map<String, String> request_headers = provider.getAuthorizationHeader(true);
        request_headers.put("accept", "application/json");
        request_headers.put("Content-Type", "application/json");

        HttpClient client = new HttpClient(provider.getProxy(), provider.getacceptInvalidCerts());
        try {
            HttpResponse response = client.get(request_url, request_headers, null);

            if (response.isSuccess()) {
                return (JSONObject) response.getResponseBodyAsJSON();
            }
        } catch (IOException | JSONException e) {
            // Ignore and return false.
        }

        return null;
    }

    /**
     * Checks if the given scanId is valid for scanning.
     *
     * @param scanId The scanId to test
     * @param provider The IAuthenticationProvider for authentication.
     * @return True if the scanId is valid. False is returned if the scanId is not valid, the request fails, or an exception occurs.
     */
    public static JSONArray getExecutionDetails(String scanId, IAuthenticationProvider provider) {
        if (provider.isTokenExpired()) {
            return null;
        }

        String request_url = provider.getServer() + String.format(API_EXECUTION_DETAILS, scanId);
        request_url += "?$filter=IsValidForIncremental%20eq%20true&%24select=Id%2C%20CreatedAt%2C%20IsValidForIncremental&%24orderby=CreatedAt%20desc";
        Map<String, String> request_headers = provider.getAuthorizationHeader(true);
        request_headers.put("accept", "application/json");
        request_headers.put("Content-Type", "application/json");

        HttpClient client = new HttpClient(provider.getProxy(), provider.getacceptInvalidCerts());
        try {
            HttpResponse response = client.get(request_url, request_headers, null);

            if (response.isSuccess()) {
                return (JSONArray) response.getResponseBodyAsJSON();
            }
        } catch (IOException | JSONException e) {
            // Ignore and return false.
        }

        return null;
    }
}
