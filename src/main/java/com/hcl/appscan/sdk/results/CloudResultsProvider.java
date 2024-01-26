/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.results;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpClient;
import com.hcl.appscan.sdk.http.HttpResponse;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.utils.SystemUtil;

public class CloudResultsProvider implements IResultsProvider, Serializable, CoreConstants {

	private static final long serialVersionUID = 1L;

	private static String DEFAULT_REPORT_FORMAT = "html"; //$NON-NLS-1$
	
	protected String m_type;
	protected String m_scanId;
	protected String m_status;
	private   String m_reportFormat;
	private   boolean m_hasResults;
	protected IScanServiceProvider m_scanProvider;
	protected IProgress m_progress;
	protected String m_message;

	protected int m_totalFindings;
        protected int m_criticalFindings;
	protected int m_highFindings;
	protected int m_mediumFindings;
	protected int m_lowFindings;
	protected int m_infoFindings;
	
	public CloudResultsProvider(String scanId, String type, IScanServiceProvider provider, IProgress progress) {
		m_type = type;
		m_scanId = scanId;
		m_hasResults = false;
		m_scanProvider = provider;
		m_progress = progress;
		m_reportFormat = DEFAULT_REPORT_FORMAT;
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
	
        protected void setHasResult(boolean value){
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

	public String getMessage() {
		return m_message;
	}

	@Override
	public void setProgress(IProgress progress) {
		m_progress = progress;
		m_scanProvider.setProgress(progress);
	}
	
	/**
	 * Specifies the format to use for reports.
	 * 
	 * @param format The format of the report. 
	 */
	public void setReportFormat(String format) {
		m_reportFormat = format;
	}
	
	protected void loadResults() {
		try {
			JSONObject items = m_scanProvider.getScanDetails(m_scanId);
			JSONObject obj = items.getJSONObject(LATEST_EXECUTION);
			m_status = obj.getString(STATUS);
			if(m_status != null && !(m_status.equalsIgnoreCase(INQUEUE) || m_status.equalsIgnoreCase(RUNNING))) {
				m_totalFindings = obj.getInt(TOTAL_ISSUES);
                                m_criticalFindings = obj.getInt(CRITICAL_ISSUES);
				m_highFindings = obj.getInt(HIGH_ISSUES);
				m_mediumFindings = obj.getInt(MEDIUM_ISSUES);
				m_lowFindings = obj.getInt(LOW_ISSUES);
				m_infoFindings = obj.getInt(INFO_ISSUES);
				m_hasResults = true;
			}
		} catch (IOException | JSONException | NullPointerException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS, e.getMessage())), e);
			m_status = FAILED;
		}
	}
	
	protected void getReport(String scanId, String format, File destination) throws IOException, JSONException {
		IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return;
		}
	
		String request_url = authProvider.getServer() + String.format(API_SCANS_REPORT, scanId, format);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
		request_headers.put(CONTENT_LENGTH, "0"); //$NON-NLS-1$
	
		HttpClient client = new HttpClient(m_scanProvider.getAuthenticationProvider().getProxy(),m_scanProvider.getAuthenticationProvider().getacceptInvalidCerts());
		HttpResponse response = client.get(request_url, request_headers, null);
	
		if (response.getResponseCode() == HttpsURLConnection.HTTP_OK) {
			if (destination.isDirectory()) {
				String fileName = DEFAULT_RESULT_NAME + "_" + SystemUtil.getTimeStamp() + "." + format; //$NON-NLS-1$ //$NON-NLS-2$
				destination = new File(destination, fileName);
			}
	
			destination.getParentFile().mkdirs();
			response.getResponseBodyAsFile(destination);
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
	
	private void checkResults() {
		if(!m_hasResults)
			loadResults();
	}
	
    protected String getReportStatus(String reportId) throws IOException, JSONException {
		IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return FAILED;
		}
	
		String request_url = authProvider.getServer() + API_REPORT_STATUS;
		request_url += String.format("?$top=100&$filter=Id eq %s&$count=false",reportId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
		request_headers.put(CONTENT_LENGTH, "0"); //$NON-NLS-1$
	
		HttpClient client = new HttpClient(m_scanProvider.getAuthenticationProvider().getProxy(),m_scanProvider.getAuthenticationProvider().getacceptInvalidCerts());
		HttpResponse response = client.get(request_url, request_headers, null);
    	
		if (response.getResponseCode() != HttpsURLConnection.HTTP_OK) {
		    return null;
		}
    	
    	JSONObject obj = (JSONObject) response.getResponseBodyAsJSON();
        JSONArray array = obj.getJSONArray(ITEMS);
        JSONObject json= (JSONObject) array.get(0);
    	return json.getString(STATUS);
    }


	public void getScanLogFile(File file , String executionId) {

		if(file != null && !file.exists()) {
			try {
				getScanLog(executionId, file);
			} catch (IOException | JSONException e) {
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_SCANLOG)), e);
			}
		}
	}

	private void getScanLog(String executionId, File destination) throws IOException, JSONException {
		IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if(authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return;
		}
		String request_url = authProvider.getServer() + String.format(API_SCANS_SCANLOGS, executionId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
		request_headers.put(CONTENT_LENGTH, "0"); //$NON-NLS-1$

		HttpClient client = new HttpClient(m_scanProvider.getAuthenticationProvider().getProxy(),m_scanProvider.getAuthenticationProvider().getacceptInvalidCerts());
		HttpResponse response = client.get(request_url, request_headers, null);

		if (response.isSuccess()) {
			if (destination.isDirectory()) {
				String fileName = "ScanLog" + "_" + SystemUtil.getTimeStamp() + "." + "zip"; //$NON-NLS-1$ //$NON-NLS-2$
				destination = new File(destination, fileName);
			}

			destination.getParentFile().mkdirs();
			response.getResponseBodyAsFile(destination);
		} else {
			JSONObject object = (JSONObject) response.getResponseBodyAsJSON();
			if (object.has(MESSAGE)) {
				m_progress.setStatus(new Message(Message.ERROR, object.getString(MESSAGE)));
			}else{
				m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_SCANLOG)));
			}
		}
	}

}
