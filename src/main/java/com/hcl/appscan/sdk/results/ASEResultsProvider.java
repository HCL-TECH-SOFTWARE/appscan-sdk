/**
 * © Copyright HCL Technologies Ltd. 2019, 2020, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.results;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpResponse;
import com.hcl.appscan.sdk.http.HttpsClient;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import com.hcl.appscan.sdk.scan.ASEScanServiceProvider;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ScanConstants;
import com.hcl.appscan.sdk.utils.SystemUtil;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

public class ASEResultsProvider implements IResultsProvider, Serializable, CoreConstants {
    private static final long serialVersionUID = 1L;

	private static String DEFAULT_REPORT_FORMAT = "json"; //$NON-NLS-1$
	
	private String m_type;
	private String m_scanId;
	private String m_status;
	private String m_reportFormat;
	private boolean m_hasResults;
	private IScanServiceProvider m_scanProvider;
	private IProgress m_progress;
	private String m_message;
	private String m_scanName;

	private int m_totalFindings;
	private int m_highFindings;
	private int m_mediumFindings;
	private int m_lowFindings;
        private int m_criticalFindings;
	private int m_infoFindings;
    public ASEResultsProvider(String scanId, String type, IScanServiceProvider provider, IProgress progress, String scanName) {
        m_type = type;
		m_scanId = scanId;
		m_hasResults = false;
		m_scanProvider = provider;
		m_progress = progress;
		m_reportFormat = DEFAULT_REPORT_FORMAT;
		m_scanName = scanName;
    }
    
    @Override
    public void getResultsFile(File file, String format) {
        if(format == null)
			format = getResultsFormat();
		
		if(file != null && !file.exists()) {
			try {
				getReport(m_scanId, format, file);
			} catch (IOException | JSONException e) {
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_RESULT)), e);
			}
		}
    }
    
    @Override
	public Collection<?> getFindings() {
		return null;
	}

	@Override
	public int getFindingsCount() {
		checkResults();
		return m_totalFindings;
	}

        @Override
        public int getCriticalCount() {
                checkResults();
                return m_criticalFindings;
        }
    
        @Override
	public int getHighCount() {
		checkResults();
		return m_highFindings;
	}

	@Override
	public int getMediumCount() {
		checkResults();
		return m_mediumFindings;
	}

	@Override
	public int getLowCount() {
		checkResults();
		return m_lowFindings;
	}

    @Override
	public int getInfoCount() {
		checkResults();
		return m_infoFindings;
	}
        
    @Override
    public String getType() {
        return m_type;
    }

    @Override
    public boolean hasResults() {
        checkResults();
		return m_hasResults;
	}
	
    protected void setHasResult(boolean value) {
        m_hasResults=value;
    }

    @Override
    public String getStatus() {
       checkResults();
       return m_status;
    }

    @Override
    public String getResultsFormat() {
        return m_reportFormat;
    }

    @Override
    public String getMessage() {
        return m_message;
    }

    @Override
    public void setReportFormat(String format) {
        m_reportFormat=format;
    }

    @Override
    public void setProgress(IProgress progress) {
        m_progress = progress;
		m_scanProvider.setProgress(progress);
    }
    
    private void loadResults() {
		try {
			m_status = getScanStatus(m_scanId);
//			m_status = getStatisticsStatus(m_scanId);
            if(m_status == null) {// In case of internet disconnect Status is set to null.
                m_status = FAILED;
            }
            if (m_status.equalsIgnoreCase("Ready")) {
                m_message = "";
                m_status=getReportPackStatus(m_scanId);
            }
			if(m_status != null && m_status.equalsIgnoreCase("Ready")) {
                JSONObject obj = m_scanProvider.getScanDetails(m_scanId);
                if (obj == null) {
                    m_message = Messages.getMessage(RESULTS_UNAVAILABLE);
                    throw new NullPointerException(Messages.getMessage(RESULTS_UNAVAILABLE));
                }

				m_totalFindings = obj.getInt(TOTAL_ISSUES);
                                m_criticalFindings = obj.getInt(CRITICAL_ISSUES);
				m_highFindings = obj.getInt(HIGH_ISSUES);
				m_mediumFindings = obj.getInt(MEDIUM_ISSUES);
				m_lowFindings = obj.getInt(LOW_ISSUES);
				m_infoFindings = obj.getInt(INFO_ISSUES);
				m_hasResults = true;
				m_message = "";
			}
			if (RUNNING.equalsIgnoreCase(m_status)) {
				m_message = "";
			} else if (m_status != null && m_status.startsWith(SUSPENDED)) {    // In case of Scan Failure ASE returns Suspended (With Reason) in Status
				this.m_message = m_status;

				String description = "";
				boolean isSuspendedByUser = false;
				if (m_status.contains("(") && m_status.contains(")")) {
					description = m_status.substring(m_status.indexOf("(") + 1, m_status.indexOf(")"));
					// If User Suspends(Pause) Job in ASE then it returns Suspended(By User) status message, Scan status is not set to FAILED
					if ("by user".equals(description.toLowerCase())) {
						m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(SUSPEND_JOB_BYUSER, "Scan Name: "  + m_scanName)));
						m_message = Messages.getMessage(SUSPEND_JOB_BYUSER, "Scan Name: "  + m_scanName);
						isSuspendedByUser = true;
					}
				}
				// If Scan is not Paused by User and we get Suspended state from ASE, Job status is set to FAILED to determine Scan has FAILED in Jenkins
				if (!isSuspendedByUser) {
					m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ScanConstants.ERROR_RUNNING_SCAN, m_status)));
					m_message = Messages.getMessage(ScanConstants.ERROR_RUNNING_SCAN, m_status);
					m_status = FAILED;
				}
			}
		} catch (IOException | JSONException | NullPointerException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS, e.getMessage())));
			m_status = FAILED;
		}
	}
	
	private void getReport(String scanId, String format, File destination) throws IOException, JSONException {
		IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return;
		}
        String reportPackId=getReportPackId(scanId);
	
		String request_url = authProvider.getServer() + String.format(ASE_REPORTS, reportPackId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
			
		HttpsClient client = new HttpsClient();
		HttpResponse response = client.get(request_url, request_headers, null);
	
		if (response.getResponseCode() == HttpsURLConnection.HTTP_OK) {
			if (destination.isDirectory()) {
				String fileName = DEFAULT_RESULT_NAME + "_" + SystemUtil.getTimeStamp() + "." + format; //$NON-NLS-1$ //$NON-NLS-2$
				destination = new File(destination, fileName);
			}
	
			destination.getParentFile().mkdirs();
            JSONObject json=getResultJson(response);
                        
			FileWriter writer=new FileWriter(destination);
            writer.write(json.toString());
            writer.flush();                                         
		} else {
			JSONObject object = (JSONObject) response.getResponseBodyAsJSON();
			if (object.has(MESSAGE)) {
				if (response.getResponseCode() == HttpsURLConnection.HTTP_BAD_REQUEST)
					m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_RESULT)));
				else
					m_progress.setStatus(new Message(Message.ERROR, object.getString(MESSAGE)));
			}
		}
	}
        
    private JSONObject getResultJson(HttpResponse response) {
	    try {
	        JSONObject object=(JSONObject) response.getResponseBodyAsJSON();
	        JSONObject reportsObject=object.getJSONObject("reports");
	        JSONArray reports=reportsObject.getJSONArray("report");
	        
	        for (Object obj:reports.toArray()) {
	            JSONObject reportObject=(JSONObject)obj;
	            if (reportObject.getString("name").equalsIgnoreCase("Security Issues")) {
	                return reportObject;
	            }
	        }
	    } catch (IOException | JSONException ex) {
	        Logger.getLogger(ASEScanServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
	    }
	    return null;
    }
	
	private void checkResults() {
		if(!m_hasResults)
			loadResults();
	}
   
    private String getReportPackId(String scanId) {
        return String.valueOf(Integer.parseInt(scanId)+1);
        // please uncomment the below code when you figure out how to parse the reponse.
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

    private String getScanStatus(String jobId) {
        IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return null;
		}
                
        String request_url = authProvider.getServer() + String.format(ASE_GET_FOLDERITEMS, jobId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true); 
		
		HttpsClient client = new HttpsClient();
		
            try {
                HttpResponse response = client.get(request_url, request_headers, null);
                if (response.getResponseCode() == HttpsURLConnection.HTTP_OK){
                    JSONObject object = (JSONObject) response.getResponseBodyAsJSON();
                    JSONObject reportPack=object.getJSONObject("content-scan-job");
                    JSONObject state=reportPack.getJSONObject("state");
                    return state.getString("name");
                }
                else {
                    m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_RESULT, "")));
                }
            } catch (IOException |JSONException ex) {
                Logger.getLogger(ASEResultsProvider.class.getName()).log(Level.SEVERE, null, ex);
            }
            return null;
    }

    private String getReportPackStatus(String jobId) {
        IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return null;
		}
        
        String reportPackId=getReportPackId(jobId);
        String request_url = authProvider.getServer() + String.format(ASE_GET_FOLDERITEMS, reportPackId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
        
		HttpsClient client = new HttpsClient();
		
            try {
                HttpResponse response = client.get(request_url, request_headers, null);
                if (response.getResponseCode() == HttpsURLConnection.HTTP_OK) {
                    JSONObject object = (JSONObject) response.getResponseBodyAsJSON();
                    JSONObject reportPack=object.getJSONObject("report-pack");
                    JSONObject state=reportPack.getJSONObject("state");
                    return state.getString("name");
                    
                }
                else {
                    m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_RESULT, "")));
                }
            } catch (IOException |JSONException ex) {
                Logger.getLogger(ASEResultsProvider.class.getName()).log(Level.SEVERE, null, ex);
            }
            return null;
    }

	private String getStatisticsStatus(String jobId) {
		IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return null;
		}

		String request_url = authProvider.getServer() + String.format(ASE_GET_FOLDER_ITEMS_STATISTICS, jobId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);

		HttpsClient client = new HttpsClient();

		try {
			HttpResponse response = client.get(request_url, request_headers, null);
			if (response.getResponseCode() == HttpsURLConnection.HTTP_OK){
				JSONObject object = (JSONObject) response.getResponseBodyAsJSON();
				if (object != null) {
					JSONObject reportPack = object.has("statistics") ? object.getJSONObject("statistics") : null;
					String state = (reportPack != null && reportPack.has("status")) ? reportPack.getString("status") : null;
					if (state != null) {
                    //  return state.split("[ (]")[0];
						return state;
					}
				}
			}
			else {
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_RESULT, "")));
			}
		} catch (IOException |JSONException ex) {
			Logger.getLogger(ASEResultsProvider.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}
}
