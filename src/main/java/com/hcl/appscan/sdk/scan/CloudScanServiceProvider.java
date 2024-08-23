/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scan;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import com.hcl.appscan.sdk.scanners.dynamic.DASTConstants;
import com.hcl.appscan.sdk.utils.FileUtil;
import com.hcl.appscan.sdk.utils.ServiceUtil;
import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONArtifact;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.app.CloudApplicationProvider;
import com.hcl.appscan.sdk.app.IApplicationProvider;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpClient;
import com.hcl.appscan.sdk.http.HttpPart;
import com.hcl.appscan.sdk.http.HttpResponse;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import com.hcl.appscan.sdk.scanners.sast.SASTConstants;

public class CloudScanServiceProvider implements IScanServiceProvider, Serializable, CoreConstants {

	private static final long serialVersionUID = 1L;

	private IProgress m_progress;
	private IAuthenticationProvider m_authProvider;
    private static final String[] DAST_FILES_EXTENSIONS = {DASTConstants.SCAN_EXTENSION, DASTConstants.SCANT_EXTENSION, DASTConstants.CONFIG_EXTENSION};
	
	public CloudScanServiceProvider(IProgress progress, IAuthenticationProvider authProvider) {
		m_progress = progress;
		m_authProvider = authProvider;
	}
  
    @Override
    public String createAndExecuteScan(String type, Map<String, String> params) {
        if(loginExpired() || (params.containsKey(APP_ID) && !verifyApplication(params.get(APP_ID).toString()))) {
            return null;
        }

        Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
        HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());

        try {
            request_headers.put("Content-Type", "application/json");
            request_headers.put("accept", "application/json");
            String request_url = m_authProvider.getServer() + String.format(API_SCANNER, type);
            
            HttpResponse response = client.post(request_url,request_headers,params);
            int status = response.getResponseCode();

            JSONObject json = (JSONObject) response.getResponseBodyAsJSON();

            if (status == HttpsURLConnection.HTTP_CREATED || status == HttpsURLConnection.HTTP_OK) {
            	String scanId = json.getString(ID);
                m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(CREATE_SCAN_SUCCESS, type.toUpperCase(), scanId)));
                String scanOverviewUrl = m_authProvider.getServer() + "/main/myapps/" + params.get(CoreConstants.APP_ID) + "/scans/" + scanId;
                m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(SCAN_OVERVIEW, type.toUpperCase(), scanOverviewUrl)));
                return scanId;
            } else if (json != null && json.has(MESSAGE)) {
                String errorResponse = json.getString(MESSAGE);
                if(json.has(FORMAT_PARAMS) && !json.isNull(FORMAT_PARAMS)) {
                    JSONArray jsonArray = json.getJSONArray(FORMAT_PARAMS);
                    if(jsonArray != null){
                        String[] messageParams = new String[jsonArray.size()];
                        for (int i = 0; i < jsonArray.size(); i++) {
                            messageParams[i] = (String)jsonArray.get(i);
                        }
                        errorResponse = MessageFormat.format(errorResponse, (Object[]) messageParams);
                    }
                }
                m_progress.setStatus(new Message(Message.ERROR, errorResponse));
            }
            else
                m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_SUBMITTING_SCAN, status)));
        } catch(IOException | JSONException e) {
            m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_SUBMITTING_SCAN, e.getLocalizedMessage())));
        }
        return null;
	  }
    @Override
    public String rescan(Map<String, String> params) {

        if (loginExpired() || (params.containsKey(APP_ID) && !verifyApplication(params.get(APP_ID).toString()))) {
            return null;
        }

        Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
        HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());

        try {
            request_headers.put("Content-Type", "application/json");
            request_headers.put("accept", "application/json");
            String request_url = m_authProvider.getServer() + String.format(API_RESCAN, params.get(CoreConstants.SCAN_ID));

            HttpResponse response = client.post(request_url, request_headers, params);
            int status = response.getResponseCode();

            JSONObject json = (JSONObject) response.getResponseBodyAsJSON();

            if (status == HttpsURLConnection.HTTP_CREATED || status == HttpsURLConnection.HTTP_OK) {
                String scanId = json.getString(SCAN_ID);
                String executionId = json.getString(ID);
                params.put(CoreConstants.EXECUTION_ID,executionId);
                m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(RESCAN_SUCCESS, scanId)));
                String scanOverviewUrl = m_authProvider.getServer() + "/main/myapps/" + params.get(CoreConstants.APP_ID) + "/scans/" + scanId;
                m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(RESCAN_OVERVIEW, scanOverviewUrl)));
                return scanId;
            } else if (json != null && json.has(MESSAGE)) {
                String errorResponse = json.getString(MESSAGE);
                if (json.has(FORMAT_PARAMS) && !json.isNull(FORMAT_PARAMS)) {
                    JSONArray jsonArray = json.getJSONArray(FORMAT_PARAMS);
                    if (jsonArray != null) {
                        String[] messageParams = new String[jsonArray.size()];
                        for (int i = 0; i < jsonArray.size(); i++) {
                            messageParams[i] = (String) jsonArray.get(i);
                        }
                        errorResponse = MessageFormat.format(errorResponse, (Object[]) messageParams);
                    }
                }
                m_progress.setStatus(new Message(Message.ERROR, errorResponse));
            } else {
                m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_SUBMITTING_SCAN, status)));
            }
        } catch (IOException | JSONException e) {
            m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_SUBMITTING_SCAN, e.getLocalizedMessage())));
        }
        return null;
    }

    @Override
	  public String submitFile(File file) throws IOException {
		  if(loginExpired())
			    return null;
		
		   m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(UPLOADING_FILE, file.getAbsolutePath())));
            String fileUploadAPI =  m_authProvider.getServer() + API_FILE_UPLOAD;
            if(!file.getName().toLowerCase().endsWith(SASTConstants.IRX_EXTENSION) && !(Arrays.asList(DAST_FILES_EXTENSIONS).contains(FileUtil.getFileExtension(file)))) {
                fileUploadAPI += "?fileType=SourceCodeArchive";
            }
		
		  List<HttpPart> parts = new ArrayList<HttpPart>();
		  parts.add(new HttpPart(CoreConstants.UPLOADED_FILE, file, "multipart/form-data")); //$NON-NLS-1$
		
		  HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
		
		  try {
			    HttpResponse response = client.postMultipart(fileUploadAPI, m_authProvider.getAuthorizationHeader(true), parts);		
			    JSONObject object = (JSONObject) response.getResponseBodyAsJSON();

			    if (object.has(MESSAGE)) {
				    m_progress.setStatus(new Message(Message.ERROR, object.getString(MESSAGE)));
			    } else {
				    return object.getString(FILE_ID);
			      }		
		  } catch (JSONException e) {
			    m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPLOADING_FILE, file, e.getLocalizedMessage())));
		   }
		   return null;
	  }
	
	@Override
	public JSONObject getScanDetails(String scanId) throws IOException, JSONException {
		if(loginExpired())
			return null;
		
		String request_url = m_authProvider.getServer() + API_BASIC_DETAILS;
		request_url += "?$filter=Id%20eq%20"+scanId;
		Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
		
		HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
                try {
		HttpResponse response = client.get(request_url, request_headers, null);
		
		if (response.getResponseCode() == HttpsURLConnection.HTTP_OK || response.getResponseCode() == HttpsURLConnection.HTTP_CREATED){
			JSONObject obj = (JSONObject) response.getResponseBodyAsJSON();
			JSONArray array = (JSONArray) obj.get(ITEMS);
			if(array.isEmpty()) {
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS_SCAN_ID,  scanId)));
			} else {
				return (JSONObject) array.getJSONObject(0);
			}
		} else if (response.getResponseCode() == -1) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS_SCAN_ID, scanId)));
		} else if (response.getResponseCode() != HttpsURLConnection.HTTP_BAD_REQUEST) {
			JSONArtifact json = response.getResponseBodyAsJSON();
			if (json != null && ((JSONObject)json).has(MESSAGE))
				m_progress.setStatus(new Message(Message.ERROR, ((JSONObject)json).getString(MESSAGE)));
			if (response.getResponseCode() == HttpsURLConnection.HTTP_FORBIDDEN && json != null &&
					((JSONObject)json).has(KEY) && ((JSONObject) json).get(KEY).equals(UNAUTHORIZED_ACTION))
				return (JSONObject) json;
		}

		if (response.getResponseCode() == HttpsURLConnection.HTTP_BAD_REQUEST)
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_INVALID_JOB_ID, scanId)));
                }
                catch(IOException | JSONException e) {
                    return new JSONObject().put(STATUS,UNKNOWN);
		}
		
		return null;
	}
	
	@Override
	public JSONArray getNonCompliantIssues(String scanId) throws IOException, JSONException {
        	if(loginExpired())
    			return null;
    		
    		String request_url = m_authProvider.getServer() + String.format(API_ISSUES_COUNT, "Scan", scanId);
    		request_url +="?applyPolicies=All&%24filter=Status%20eq%20%27Open%27%20or%20Status%20eq%20%27InProgress%27%20or%20Status%20eq%20%27Reopened%27%20or%20Status%20eq%20%27New%27&%24apply=groupby%28%28Status%2CSeverity%29%2Caggregate%28%24count%20as%20N%29%29";
    		Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
    		request_headers.put("Content-Type", "application/json; charset=UTF-8");
    		request_headers.put("Accept", "application/json");
    		
    		HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
    		HttpResponse response = client.get(request_url, request_headers, null);
    		
    		if (response.isSuccess()) {
    			JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
    			return (JSONArray) json.getJSONArray("Items");
                }

    		if (response.getResponseCode() == HttpsURLConnection.HTTP_BAD_REQUEST)
    			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_INFO, "Scan", scanId)));
            else {
                JSONObject obj=(JSONObject)response.getResponseBodyAsJSON();
                if (obj!=null && obj.has(MESSAGE)){
                    m_progress.setStatus(new Message(Message.ERROR, obj.getString(MESSAGE)));
                }
                else {
                    m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS, response.getResponseCode())));
                }
            }
                            
    		return null;
	}

	@Override
	public JSONArray getNonCompliantIssues(Map<String, String> params) throws IOException, JSONException {
        	if(loginExpired())
    			return null;

        	String request_url = m_authProvider.getServer() + String.format(API_ISSUES_COUNT, "ScanExecution", params.get(CoreConstants.EXECUTION_ID));
        	request_url +="?applyPolicies=All&%24filter=Status%20eq%20%27Open%27%20or%20Status%20eq%20%27InProgress%27%20or%20Status%20eq%20%27Reopened%27%20or%20Status%20eq%20%27New%27&%24apply=groupby%28%28Status%2CSeverity%29%2Caggregate%28%24count%20as%20N%29%29";
        	Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
        	request_headers.put("Content-Type", "application/json; charset=UTF-8");
        	request_headers.put("Accept", "application/json");

        	HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
        	HttpResponse response = client.get(request_url, request_headers, null);

        	if (response.isSuccess()) {
    			JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
    			return (JSONArray) json.getJSONArray("Items");
        	}

        	if (response.getResponseCode() == HttpsURLConnection.HTTP_BAD_REQUEST)
    			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_INFO, "Scan", params.get(CoreConstants.SCAN_ID))));
        	else {
    			JSONObject obj=(JSONObject)response.getResponseBodyAsJSON();
    			if (obj!=null && obj.has(MESSAGE)){
                            m_progress.setStatus(new Message(Message.ERROR, obj.getString(MESSAGE)));
    			}
    			else {
                            m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS, response.getResponseCode())));
    			}
        	}

        	return null;
	}
	
	@Override
	public IAuthenticationProvider getAuthenticationProvider() {
		return m_authProvider;
	}
	
	private boolean loginExpired() {
		if(m_authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return true;
		}
		return false;
	}
	
	private boolean verifyApplication(String appId) {
		if(appId != null && !appId.trim().equals("")) { //$NON-NLS-1$
			IApplicationProvider provider = new CloudApplicationProvider(m_authProvider);
			if(provider.getApplications() != null && provider.getApplications().keySet().contains(appId))
				return true;
		}
		m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_INVALID_APP, appId)));
		return false;
	}
	
	@Override
	public void setProgress(IProgress progress) {
		m_progress = progress;
	}
}
