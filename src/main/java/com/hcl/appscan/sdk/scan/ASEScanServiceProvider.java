/**
 * © Copyright HCL Technologies Ltd. 2019,2020, 2025.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scan;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.auth.IASEAuthenticationProvider;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpPart;
import com.hcl.appscan.sdk.http.HttpResponse;
import com.hcl.appscan.sdk.http.HttpsClient;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;

import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

public class ASEScanServiceProvider implements IScanServiceProvider, Serializable, CoreConstants {
	private IProgress m_progress;
	private IASEAuthenticationProvider m_authProvider;
	
	public ASEScanServiceProvider(IProgress progress, IAuthenticationProvider authProvider) {
		m_progress = progress;
		m_authProvider = (IASEAuthenticationProvider)authProvider;
	}

    @Override
    public String createAndExecuteScan(String type, Map<String, String> params) {
        
    	String jobId=createJob(params);
    	
    	if (jobId!=null) {
		jobId = updateJob(params, jobId);
    	}
        if (jobId!=null && runScanJob(jobId)){
            return jobId;
        }
        return null;
    }
    
    private String createJob(Map<String, String> params) {
    	
        if(loginExpired())
           return null;
        
        Map<String, String> createJobParams = getcreateJobParams(params);
        m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(CREATING_JOB)));
        
        // TODO : correct it .
        String templateId = createJobParams.get("templateId");
        createJobParams.remove("templateId");
		
        String request_url = m_authProvider.getServer() + String.format(ASE_CREATEJOB_TEMPLATE_ID, templateId);
        Map<String, String> request_headers = getRequestHeaders();
		
		HttpsClient client = new HttpsClient();
		
		try {
			HttpResponse response = client.postForm(request_url, request_headers, createJobParams);
			int status = response.getResponseCode();

			// Handle scenarios of invalid input parameters during job creation.
			// Currently ASE APIs do not return a valid response for invalid inputs 
			// hence, making the check here for better error handling
			if (status == HttpsURLConnection.HTTP_BAD_REQUEST
					|| status == HttpsURLConnection.HTTP_NOT_FOUND) {
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(
						ERROR_CREATE_JOB, Messages.getMessage(ERROR_INVALID_DETAILS))));
				return null;
			}

			JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
			
			if (status == HttpsURLConnection.HTTP_CREATED) {
				m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(CREATE_JOB_SUCCESS)));
				return json.getString(ASE_ID_ATTRIBUTE);
			}
			else if (json != null && json.has(MESSAGE))
				m_progress.setStatus(new Message(Message.ERROR, json.getString(MESSAGE)));
			else
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_CREATE_JOB, status)));
		} catch(IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_CREATE_JOB, e.getLocalizedMessage())));
		}
		return null;
    }
    
    private Map<String,String> getcreateJobParams(Map<String,String> properties) {
        Map<String,String> apiParams= new HashMap<>();
        apiParams.put("testPolicyId", properties.get("testPolicyId"));
        apiParams.put("folderId",properties.get("folder"));
        apiParams.put("applicationId",properties.get("application"));
        apiParams.put("name", properties.get("ScanName"));
        apiParams.put("templateId", properties.get("templateId"));
        apiParams.put("description", properties.get("description"));
        apiParams.put("contact", properties.get("contact"));
        return apiParams;
    }
    
	private String updateJob(Map<String, String> params, String jobId) {
		String scanTypeValue = params.getOrDefault("scanType", "");

		if (!handleStartingURL(params, jobId, scanTypeValue)) return null;
		if (!handleAgentServer(params, jobId)) return null;
		if (!handleLoginManagement(params, jobId)) return null;
		if (!handleExploreData(params, jobId)) return null;
		if (!handleScanType(params, jobId, scanTypeValue)) return null;
		if (!handleTestOptimization(params, jobId)) return null;
		if (!handlePostmanCollection(params, jobId, scanTypeValue)) return null;

		return jobId;
	}

	private boolean handleStartingURL(Map<String, String> params, String jobId, String scanType) {
		return scanType.equals(POSTMAN_COLLECTION) || params.get("startingURL").isEmpty() ||
				updatescantJob(getUpdatescantJobParams("StartingUrl", params.get("startingURL"), "false"), jobId);
	}

	private boolean handleAgentServer(Map<String, String> params, String jobId) {
		return params.get("agentServer").isEmpty() || updateAgentServer(params, jobId);
	}

	private boolean handleLoginManagement(Map<String, String> params, String jobId) {
		String loginType = params.getOrDefault("loginType", "");
		if (loginType.isEmpty()) return true;

		if (!updatescantJob(getUpdatescantJobParams("LoginMethod", loginType, "false"), jobId)) return false;

		if (loginType.equals("Automatic")) {
			if (!updatescantJob(getUpdatescantJobParams("LoginUsername", params.get("userName"), "false"), jobId)) return false;
			if (!updatescantJob(getUpdatescantJobParams("LoginPassword", params.get("password"), "true"), jobId)) return false;
		}

		if (loginType.equals("Manual")) {
			File trafficFile = getFile(params.get("trafficFile"));
			if (trafficFile != null && !updateTrafficJob(trafficFile, jobId, "login")) return false;
		}

		return true;
	}

	private boolean handleExploreData(Map<String, String> params, String jobId) {
		String exploreData = params.getOrDefault("exploreData", "");
		return exploreData.isEmpty() || updateTrafficJob(getFile(exploreData), jobId, "add");
	}

	private boolean handleScanType(Map<String, String> params, String jobId, String scanType) {
		return scanType.isEmpty() || scanType.equals(POSTMAN_COLLECTION) || updateScanTypeJob(params, jobId);
	}

	private boolean handleTestOptimization(Map<String, String> params, String jobId) {
		String testOpt = params.getOrDefault("testOptimization", "");
		return testOpt.isEmpty() || updatescantJob(getUpdatescantJobParams("TestOptimization", testOpt, "false"), jobId);
	}

	private boolean handlePostmanCollection(Map<String, String> params, String jobId, String scanType) {
		return !scanType.equals(POSTMAN_COLLECTION) || createPostmanCollectionJob(params, jobId);
	}


	private boolean updatescantJob(Map<String, String> params, String jobId) {

		if(loginExpired())
			return false;

		String request_url = m_authProvider.getServer() + String.format(ASE_UPDSCANT, jobId);
		Map<String, String> request_headers = getRequestHeaders();

		HttpsClient client = new HttpsClient();

		try {
			HttpResponse response = client.postForm(request_url, request_headers, params);
			int status = response.getResponseCode();
			if (status != HttpsURLConnection.HTTP_OK) {
				return false;
			}
		} catch(IOException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
			return false;
		}
		return true;
	}
    
	private boolean updateScanTypeJob (Map<String, String> params, String jobId) {

		if(loginExpired())
			return false;

		String request_url = m_authProvider.getServer() + String.format(ASE_SCAN_TYPE) + "?scanTypeId=" + ASEScanType.scanTypeCode(params.get("scanType")) + "&jobId="+ jobId;
		Map<String, String> request_headers = getRequestHeaders();
		
		HttpsClient client = new HttpsClient();

		try {
			HttpResponse response = client.put(request_url, request_headers, null);
			int status = response.getResponseCode();
			if (status != HttpsURLConnection.HTTP_OK) {
				return false;
			}
		} catch(IOException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
			return false;
		}
		return true;
	}
    
	private boolean updateTrafficJob(File file, String jobId, String action) {

		if(loginExpired() || file == null)
			return false;

		String request_url = m_authProvider.getServer() + String.format(ASE_UPDTRAFFIC, jobId, action);
		Map<String, String> request_headers = getRequestHeaders();
		
		List<HttpPart> parts = new ArrayList<HttpPart>();
		
		try {
		    parts.add(new HttpPart(ASE_UPLOADED_FILE, file, "multipart/form-data")); //$NON-NLS-1$
		} catch (IOException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
			return false;
		}
		
		HttpsClient client = new HttpsClient();

		try {
			HttpResponse response = client.postMultipart(request_url, request_headers, parts);
			int status = response.getResponseCode();
			if (status != HttpsURLConnection.HTTP_OK) {
                		JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
                		if(json != null && json.has("errorMessage")){
                    			m_progress.setStatus(new Message(Message.ERROR, json.getString("errorMessage")));
                	}
                		return false;
			}
		} catch(IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
			return false;
		}
		return true;
	}
    
	private boolean updateAgentServer (Map<String, String> params, String jobId ) {
		if(loginExpired())
			return false;

		String request_url = m_authProvider.getServer() + String.format(ASE_UPDTAGENT, jobId, params.get("agentServer"));
		Map<String, String> request_headers = getRequestHeaders();

		HttpsClient client = new HttpsClient();
		 
		try {
			HttpResponse response = client.postForm(request_url, request_headers, params);
			int status = response.getResponseCode();
			if (status != HttpsURLConnection.HTTP_OK) {
				return false;
			}
		} catch(IOException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
			return false;
		}
		return true;
	}
	
	private Map<String,String> getUpdatescantJobParams(String scantNodeXpath, String scantNodeNewValue, String encryptNodeValue) {
		Map<String,String> apiParams= new HashMap<>();
		apiParams.put("scantNodeXpath", scantNodeXpath);
		apiParams.put("scantNodeNewValue", scantNodeNewValue);
		apiParams.put("encryptNodeValue", encryptNodeValue);
		//apiParams.put("allowExploreDataUpdate", "0");
		return apiParams;
	}

	private boolean createPostmanCollectionJob(Map<String, String> params, String jobId) {

		if(loginExpired() || params == null)
			return false;

		String request_url = m_authProvider.getServer() + String.format(ASE_POSTMAN_COLLECTION, jobId);
		Map<String, String> request_headers = getRequestHeaders();

		List<HttpPart> parts = new ArrayList<HttpPart>();
		HttpsClient client = new HttpsClient();

		try {
			addAllFileParts(params, parts);

			if(params.containsKey("additionalDomains")) {
				parts.add(new HttpPart("additionalDomains", params.get("additionalDomains"))); //$NON-NLS-1$
			}
			parts.add(new HttpPart("asc_xsrf_token", request_headers.get("asc_xsrf_token"))); //$NON-NLS-1$


			HttpResponse response = client.postMultipart(request_url, request_headers, parts);
			int status = response.getResponseCode();
			if (status == HttpsURLConnection.HTTP_OK) {
				m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(UPDATE_POSTMAN_COLLECTION_SUCCESS, jobId)));
			} else {
				JSONObject json = (JSONObject) response.getResponseBodyAsJSON();
				if(json != null && json.has("errorMessage")){
					m_progress.setStatus(new Message(Message.ERROR, json.getString("errorMessage")));
				} else {
					m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, status)));
				}
				return false;
			}
		} catch(IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_UPDATE_JOB, e.getLocalizedMessage())));
			return false;
		}
		return true;
	}
   
	private File getFile(String fileLocation) {
		if(fileLocation != null && new File(fileLocation).isFile()) {
			File file = new File(fileLocation);
			return file;
		}
		m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_FILE_NOT_FOUND, fileLocation)));
		return null;
	}

	private void addAllFileParts(Map<String, String> params, List<HttpPart> parts) throws IOException {
		String[][] filePartMappings = {
				{"postmanCollectionFile", "postmanCollectionFile"},
				{"environmentalVariablesFile", "postmanEnvironmentFile"},
				{"globalVariablesFile", "postmanGlobalFile"},
				{"additionalFiles", "postmanAdditionalFiles"}
		};

		for (String[] mapping : filePartMappings) {
			addFilePart(params, parts, mapping[0], mapping[1]);
		}
	}


	private void addFilePart(Map<String, String> params, List<HttpPart> parts, String paramKey, String partName) throws IOException {
		String filePath = params.get(paramKey);
		if (filePath != null && !filePath.isEmpty()) {
			File file = getFile(filePath);
			if (file != null) {
				parts.add(new HttpPart(partName, file, "multipart/form-data")); //$NON-NLS-1$
			}
		}
	}


	private boolean runScanJob(String jobId) {
      
       if(loginExpired())
			return false;
		
		m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(EXECUTING_JOB)));
		
        String eTag = "";
        eTag = getEtag(jobId);
		String request_url = m_authProvider.getServer() + String.format(ASE_RUN_JOB_ACTION, jobId);
		Map<String, String> request_headers = getRequestHeaders();
        request_headers.put("If-Match", eTag);
        Map<String ,String> params= new HashMap<>();
        params.put("type", "run");
		
		HttpsClient client = new HttpsClient();
		
		try {
			HttpResponse response = client.postForm(request_url, request_headers, params);
			int status = response.getResponseCode();
			if (status == HttpsURLConnection.HTTP_OK) {
				m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(EXECUTE_JOB_SUCCESS)));
				return true;
			}
			else
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_EXECUTE_JOB, status)));
		} catch(IOException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_EXECUTE_JOB, e.getLocalizedMessage())));
		}
		return false;
    }
    
    private String getEtag(String jobId) {

    	if(loginExpired())
			return null;
		
		String request_url = m_authProvider.getServer() + String.format(ASE_GET_JOB, jobId);
		Map<String, String> request_headers = getRequestHeaders();
		
		HttpsClient client = new HttpsClient();
		
		try {
			HttpResponse response = client.get(request_url, request_headers, null);
			int status = response.getResponseCode();
			if (status == HttpsURLConnection.HTTP_OK) {
				return response.getHeaderField("ETag");
			}
		} catch(IOException e) {
			return null;
		}
		return null;
    }
    
    private boolean loginExpired() {
        if(m_authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return true;
		}
		return false;
	}

    @Override
    public String submitFile(File file) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public JSONObject getScanDetails(String jobId) throws IOException, JSONException {
        if(loginExpired())
			return null;
		String reportPackId=getReportPackId(jobId);
		String request_url = m_authProvider.getServer() + String.format(ASE_REPORTS, reportPackId);
		Map<String, String> request_headers = getRequestHeaders();
		
		HttpsClient client = new HttpsClient();
		HttpResponse response = client.get(request_url, request_headers, null);
		
		if (response.getResponseCode() == HttpsURLConnection.HTTP_OK || response.getResponseCode() == HttpsURLConnection.HTTP_CREATED)			
                        return getResultJson(response);

		if (response.getResponseCode() == HttpsURLConnection.HTTP_BAD_REQUEST)
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_INVALID_JOB_ID, jobId)));
		
		return null;
    }

    @Override
    public JSONArray getNonCompliantIssues(String scanId) throws IOException, JSONException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public JSONArray getNonCompliantIssuesUsingExecutionId(String executionId) throws IOException, JSONException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    @Override
     public String rescan(String scanId, Map<String, String> params) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public IAuthenticationProvider getAuthenticationProvider() {
        return m_authProvider;
    }

    @Override
    public void setProgress(IProgress progress) {
        m_progress = progress;
    }

    @Override
    public JSONArray getBaseScanDetails(String scanId) {
        return null;
    }

    private String getReportPackId(String jobId) {
        return String.valueOf(Integer.parseInt(jobId)+1);
        // Uncomment the below code when you figure out how to parse the reponse.
        // currently the reponse is returned as array which makes no sense.
        /*IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return null;
		}
                
                
		String request_url = authProvider.getServer() + String.format(ASE_REPORTPACK, scanId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
                request_headers.put(CONTENT_TYPE, "application/json; utf-8"); //$NON-NLS-1$
		request_headers.put(CHARSET, UTF8);
                request_headers.put("Accept", "application/json"); //$NON-NLS-1$ //$NON-NLS-2$
		
		HttpsClient client = new HttpsClient();
		
            try {
                HttpResponse response = client.get(request_url, request_headers, null);
                if (response.getResponseCode() == HttpsURLConnection.HTTP_OK){
                    JSONObject object = (JSONObject) response.getResponseBodyAsJSON();
                    JSONArray array=object.getJSONArray("");
                    JSONObject obj=array.getJSONObject(0);
                    return obj.getString("reportPackId");
                }
                else {
                    m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_RESULT)));
                }
            } catch (IOException |JSONException ex) {
                Logger.getLogger(ASEResultsProvider.class.getName()).log(Level.SEVERE, null, ex);
            }
            return null;
            */
    }

    private JSONObject getResultJson(HttpResponse response) {
        JSONObject result;
        try {
            JSONObject object=(JSONObject) response.getResponseBodyAsJSON();
            JSONObject reportsObject=object.getJSONObject("reports");
            JSONArray reports=reportsObject.getJSONArray("report");
            outer:
            for (Object obj:reports.toArray()){
                JSONObject reportObject=(JSONObject)obj;
                if (reportObject.getString("name").equalsIgnoreCase("Security Issues")) {
                    result= new JSONObject();
                    JSONObject issueCountsSeverity=reportObject.getJSONObject("issue-counts-severity");
                    JSONArray issueCount=issueCountsSeverity.getJSONArray("issue-count");
                    int totalCount=0;
                    int count;
                    inner:
                    for (Object severity: issueCount.toArray()) {
                        JSONObject severityCount=(JSONObject) severity;
                        JSONObject severityDetails=severityCount.getJSONObject("severity");
                        count=Integer.parseInt(severityCount.getString("count"));
                        switch(severityDetails.getString("name")) {
                            case "Critical":
                                result.put("NCriticalIssues", count);
                                totalCount=totalCount+count;
                                break;
                            case "High":
                                result.put("NHighIssues", count);
                                totalCount=totalCount+count;
                                break;
                            case "Medium":
                                result.put("NMediumIssues", count);
                                totalCount=totalCount+count;
                                break;
                            case "Low":
                                result.put("NLowIssues", count);
                                totalCount=totalCount+count;
                                break;
                            case "Information":
                                result.put("NInfoIssues", count);
                                totalCount=totalCount+count;
                                break;
                            default:
                                totalCount=totalCount+count;
                                break;
                        }
                    }
                    result.put("NIssuesFound", totalCount);
                    return result;
                }
            }
        } catch (IOException | JSONException ex) {
            Logger.getLogger(ASEScanServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

	private Map<String, String> getRequestHeaders() {
		Map<String, String> request_headers = m_authProvider.getAuthorizationHeader(true);
		request_headers.put(CONTENT_TYPE, "application/json; utf-8"); //$NON-NLS-1$
		request_headers.put(CHARSET, UTF8);
		request_headers.put("Accept", "application/json"); //$NON-NLS-1$ //$NON-NLS-2$
		return request_headers;
	}
}
