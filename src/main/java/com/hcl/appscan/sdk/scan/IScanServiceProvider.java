/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017,2018. 
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scan;

import java.io.File;
import java.io.IOException;
import java.util.Map;

import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpResponse;
import com.hcl.appscan.sdk.logging.IProgress;

/**
 * A provider of scanning services.
 */
public interface IScanServiceProvider {

	/**
	 * Creates and executes a scan.
	 * 
	 * @param type The type of scan to execute. For example DynamicAnalyzer, MobileAnalyzer, or StaticAnalyzer.
	 * @param params A Map of scan parameters.
	 * @return The id of the submitted scan, if successful.  Otherwise, null.
	 */
	public String createAndExecuteScan(String type, Map<String, String> params);

    	/**
     	 * Submits a file for scanning.
     	 *
     	 * @param file The file to submit.
     	 * @return The id of the submitted file.
     	 * @throws IOException If an error occurs.
     	 */
    	public String submitFile(File file) throws IOException;

	/**
	 * Gets the detailed description of a scan in JSON format.
	 * 
	 * @param scanId The id of the scan to retrieve the description.
	 * @return JSONObject The detailed description in JSON.
	 * @throws IOException If an error occurs.
	 * @throws JSONException If an error occurs.
	 */
	public JSONObject getScanDetails(String scanId) throws IOException, JSONException;
	
	/**
	 * Gets the non compliant issues in JSON format.
	 * 
	 * @param scanId The id of the scan to retrieve all the non compliant issues.
	 * @return JSONArray containing the issues as JSON objects.
	 * @throws IOException If an error occurs.
	 * @throws JSONException If an error occurs.
	 */
	public JSONArray getNonCompliantIssues(String scanId) throws IOException, JSONException;
	
	/**
	 * Gets the {@link IAuthenticationProvider} used to authenticate with a scanning service.
	 * 
	 * @return The {@link IAuthenticationProvider}.
	 */
	
	public IAuthenticationProvider getAuthenticationProvider();
	
	/**
	 * Sets the {@link IProgress} used to record status messages.
	 * @param progress The {@link IProgress}.
	 */
	public void setProgress(IProgress progress);
}
