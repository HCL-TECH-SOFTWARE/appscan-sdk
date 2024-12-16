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
import java.util.HashMap;

import javax.net.ssl.HttpsURLConnection;

import com.hcl.appscan.sdk.logging.DefaultProgress;
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

	public CloudScanServiceProvider(IAuthenticationProvider authProvider) {
		this(new DefaultProgress(), authProvider);
	}
  
    @Override
    public String createAndExecuteScan(String type, Map<String, String> params) {
        String requestUrl = m_authProvider.getServer() + String.format(API_SCANNER, type);
        String progressMessage = Messages.getMessage(CREATE_SCAN_SUCCESS,type.toUpperCase());
        String overviewMessage = Messages.getMessage(SCAN_OVERVIEW,type.toUpperCase());
        return executeScan(requestUrl, params, progressMessage, overviewMessage);
	  }
    
    @Override
    public String rescan(String scanId, Map<String, String> params) {
        String requestUrl = m_authProvider.getServer() + String.format(API_RESCAN, scanId);

        Map<String, String> updateParams = new HashMap<>();
        updateParams.put("Name", params.remove(CoreConstants.SCAN_NAME));
        updateParams.put("EnableMailNotifications", params.remove(CoreConstants.EMAIL_NOTIFICATION));
        updateParams.put("FullyAutomatic", params.remove("FullyAutomatic"));
        updateScanData(updateParams, scanId);

        String progressMessage = Messages.getMessage(RESCAN_SUCCESS);
        String overviewMessage = Messages.getMessage(RESCAN_OVERVIEW);
        return executeScan(requestUrl, params, progressMessage, overviewMessage);
    }

    //private method to handle common logic
    private String executeScan(String requestUrl, Map<String, String> params, String successMessageKey, String overviewMessageKey) {
        if (loginExpired() || (params.containsKey(APP_ID) && !verifyApplication(params.get(APP_ID).toString()))) {
            return null;
        }

        Map<String, String> requestHeaders = m_authProvider.getAuthorizationHeader(true);
        HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());

        try {
            requestHeaders.put("Content-Type", "application/json");
            requestHeaders.put("accept", "application/json");

            HttpResponse response = client.post(requestUrl, requestHeaders, params);
            int status = response.getResponseCode();
            JSONObject json = (JSONObject) response.getResponseBodyAsJSON();

            if (status == HttpsURLConnection.HTTP_CREATED || status == HttpsURLConnection.HTTP_OK) {
                String id = json.getString(ID);
                String scanOverviewUrl;
                if(params.containsKey(SCAN_ID)) {
                    String scanId= params.get(SCAN_ID);
                    scanOverviewUrl = m_authProvider.getServer() + "/main/myapps/" + params.get(CoreConstants.APP_ID) + "/scans/" + scanId;
                } else {
                    scanOverviewUrl = m_authProvider.getServer() + "/main/myapps/" + params.get(CoreConstants.APP_ID) + "/scans/" + id;
                }
                m_progress.setStatus(new Message(Message.INFO, successMessageKey + " " + id));
                m_progress.setStatus(new Message(Message.INFO, overviewMessageKey + " " + scanOverviewUrl));
                return id;
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

	public JSONObject getScanDetails(String type, String scanId) {
		if (loginExpired()) {
			return null;
		}

		String request_url = m_authProvider.getServer() + String.format(API_SCANNER_DETAILS, ServiceUtil.scanTypeShortForm(type), scanId);
		Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
		request_headers.put("accept", "application/json");
		request_headers.put("Content-Type", "application/json");

		HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
		try {
			HttpResponse response = client.get(request_url, request_headers, null);

			if (response.isSuccess()) {
				return (JSONObject) response.getResponseBodyAsJSON();
			}
		} catch (IOException | JSONException e) {
			// Ignore and move on.
		}

		return null;
	}
	
	@Override
	public JSONArray getNonCompliantIssues(String scanId) throws IOException, JSONException {
        return getNonCompliantIssues("Scan", scanId);
	}

	@Override
	public JSONArray getNonCompliantIssuesUsingExecutionId(String executionId) throws IOException, JSONException {
        return getNonCompliantIssues("ScanExecution", executionId);
	}

    //private method to handle common logic
    private JSONArray getNonCompliantIssues(String idType, String id) throws IOException, JSONException {
        if (loginExpired())
            return null;

        String requestUrl = m_authProvider.getServer() + String.format(API_ISSUES_COUNT, idType, id);
        requestUrl += "?applyPolicies=All&%24filter=Status%20eq%20%27Open%27%20or%20Status%20eq%20%27InProgress%27%20or%20Status%20eq%20%27Reopened%27&%24apply=groupby%28%28Status%2CSeverity%29%2Caggregate%28%24count%20as%20N%29%29";

        Map<String, String> requestHeaders = m_authProvider.getAuthorizationHeader(true);
        requestHeaders.put("Content-Type", "application/json; charset=UTF-8");
        requestHeaders.put("Accept", "application/json");

        HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
        HttpResponse response = client.get(requestUrl, requestHeaders, null);

        if (response.isSuccess()) {
            JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
            return (JSONArray) json.getJSONArray("Items");
        }

        if (response.getResponseCode() == HttpsURLConnection.HTTP_BAD_REQUEST) {
            m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_INFO, idType, id)));
        } else {
            JSONObject obj = (JSONObject) response.getResponseBodyAsJSON();
            if (obj != null && obj.has(MESSAGE)) {
                m_progress.setStatus(new Message(Message.ERROR, obj.getString(MESSAGE)));
            } else {
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

	@Override
	public JSONArray getBaseScanDetails(String scanId) {
		if (loginExpired()) {
			return null;
		}

		String request_url = m_authProvider.getServer() + String.format(API_EXECUTION_DETAILS, scanId);
		request_url += "?$filter=IsValidForIncremental%20eq%20true&%24select=Id%2C%20CreatedAt%2C%20IsValidForIncremental&%24orderby=CreatedAt%20desc";
		Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
		request_headers.put("accept", "application/json");
		request_headers.put("Content-Type", "application/json");

		HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
		try {
			HttpResponse response = client.get(request_url, request_headers, null);

			if (response.isSuccess()) {
				return (JSONArray) response.getResponseBodyAsJSON();
			}
		} catch (IOException | JSONException e) {
			// Ignore and move on.
		}

		return null;
	}

	public void updateScanData(Map<String, String> params, String scanId) {
		if (loginExpired()) {
			return;
		}

		String request_url = m_authProvider.getServer() + String.format(API_SCANNER,scanId);
		Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
		request_headers.put("accept", "application/json");
		request_headers.put("Content-Type", "application/json");

		HttpClient client = new HttpClient(m_authProvider.getProxy(), m_authProvider.getacceptInvalidCerts());
		try {
			HttpResponse response = client.put(request_url, request_headers, params);
			if (response.getResponseCode() == HttpsURLConnection.HTTP_NO_CONTENT) {
				m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(UPDATE_JOB)));
			}
		} catch (IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
		}
	}
}
