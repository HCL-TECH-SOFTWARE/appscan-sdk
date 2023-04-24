/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.auth;

import java.net.Proxy;
import java.util.Map;

public interface IAuthenticationProvider {

	/**
	 * Checks if the stored token has expired.
	 * 
	 * @return True if the token has expired.
	 */
	public boolean isTokenExpired();
	
	/**
	 * Retrieves the authorization header for use in requests.
	 * 
	 * @param persist True for a persistent connection.
	 * @return The authorization header
	 */
	public Map<String, String> getAuthorizationHeader(boolean persist);
	
	/**
	 * Gets the server url.
	 * 
	 * @return The server url.
	 */
	public String getServer();
	
	/**
	 * Saves the connection data.
	 * 
	 * @param connection The connection data to save.
	 */
	public void saveConnection(String connection);
	
	/**
	 * Gets the {@link Proxy} to use for connections.
	 * @return The proxy
	 */
	public Proxy getProxy();

    public boolean getCertificates();
}
