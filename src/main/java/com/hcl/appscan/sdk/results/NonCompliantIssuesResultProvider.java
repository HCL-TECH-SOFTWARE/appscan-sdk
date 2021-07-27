/**
 * © Copyright HCL Technologies Ltd. 2018,2020,2021.
 */
package com.hcl.appscan.sdk.results;

import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.http.HttpClient;
import com.hcl.appscan.sdk.http.HttpResponse;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.utils.SystemUtil;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

/**
 *
 * @author anurag-s
 */
public class NonCompliantIssuesResultProvider extends CloudResultsProvider {
	private static final long serialVersionUID = 1L;
	private static final String SCOPE = "Scan";

	public NonCompliantIssuesResultProvider(String scanId, String type, IScanServiceProvider provider,
			IProgress progress) {
		super(scanId, type, provider, progress);
	}

	@Override
	protected void loadResults() {
		try {
			JSONObject obj = m_scanProvider.getScanDetails(m_scanId);
			if (obj == null) {
				m_status = FAILED;
				return;
			} else if (obj.has(KEY) && obj.get(KEY).equals(UNAUTHORIZED_ACTION)) {
				m_status = FAILED;
				return;
			} else if (obj.has(STATUS) && obj.get(STATUS).equals(UNKNOWN)) {
                m_status = UNKNOWN;
                return;
			}

			obj = (JSONObject) obj.get(LATEST_EXECUTION);

			m_status = obj.getString(STATUS);
			if (FAILED.equalsIgnoreCase(m_status) && obj.has(USER_MESSAGE)) {
				m_progress.setStatus(new Message(Message.ERROR, obj.getString(USER_MESSAGE)));
				m_message = obj.getString(USER_MESSAGE);
			} else if (PAUSED.equalsIgnoreCase(m_status)) {
				m_progress.setStatus(new Message(Message.INFO, Messages.getMessage(SUSPEND_JOB_BYUSER, "Scan Id: " + m_scanId)));
				m_message = Messages.getMessage(SUSPEND_JOB_BYUSER, "Scan Id: " + m_scanId);
			} else if (m_status != null && !(m_status.equalsIgnoreCase(INQUEUE) || m_status.equalsIgnoreCase(RUNNING) || m_status.equalsIgnoreCase(PAUSING))) {
				JSONArray array = m_scanProvider.getNonCompliantIssues(m_scanId);
				m_totalFindings = 0;
				
				for (int i = 0; i < array.length(); i++) {
					JSONObject jobj = array.getJSONObject(i);
					String sev = jobj.getString("Severity");
					int count = jobj.getInt("Count");
					
					switch (sev.toLowerCase()) {
					case "high":
						m_highFindings = count;
						m_totalFindings += count;
						break;
					case "medium":
						m_mediumFindings = count;
						m_totalFindings += count;
						break;
					case "low":
						m_lowFindings = count;
						m_totalFindings += count;
						break;
					case "informational":
						m_infoFindings = count;
						m_totalFindings += count;
						break;
					default:
						m_totalFindings += count;
						break;
					}
				}
				setHasResult(true);
				m_message = "";
			} else if (RUNNING.equalsIgnoreCase(m_status)) m_message = "";
		} catch (IOException | JSONException | NullPointerException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS, e.getMessage())),
					e);
			m_status = FAILED;
		}

	}

	@Override
	protected void getReport(String scanId, String format, File destination) throws IOException, JSONException {

		String reportId = createNonCompliantIssuesReport(scanId, format);

		if (reportId == null) {
			return;
		}

		String status = getReportStatus(reportId);

		while (!status.equalsIgnoreCase(READY) && !status.equalsIgnoreCase(FAILED)) {
			try {
				Thread.sleep(3000);
				status = getReportStatus(reportId);
			} catch (InterruptedException e) {
				// ignore
			}
		}

		if (!status.equalsIgnoreCase(READY)) {
			throw new IOException("error.getting.issues");
		}

		HttpResponse response = downloadNonCompliantIssuesReport(reportId);
		if (destination.isDirectory()) {
			String fileName = DEFAULT_RESULT_NAME + "_" + SystemUtil.getTimeStamp() + "." + format; //$NON-NLS-1$ //$NON-NLS-2$
			destination = new File(destination, fileName);
		}

		destination.getParentFile().mkdirs();
		response.getResponseBodyAsFile(destination);
	}

	private HttpResponse downloadNonCompliantIssuesReport(String reportId) throws IOException, JSONException {
		IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if (authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return null;
		}
		String request_url = authProvider.getServer() + String.format(API_DOWNLOAD_REPORT, reportId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
		request_headers.put(CONTENT_LENGTH, "0"); //$NON-NLS-1$

		HttpClient client = new HttpClient(m_scanProvider.getAuthenticationProvider().getProxy());
		HttpResponse response = client.get(request_url, request_headers, null);
		int responseCode = response.getResponseCode();
		if (responseCode == HttpsURLConnection.HTTP_OK)
			return response;
		else if (responseCode == HttpsURLConnection.HTTP_INTERNAL_ERROR)
			return downloadNonCompliantIssuesReport(reportId);
		else {
			JSONObject object = (JSONObject) response.getResponseBodyAsJSON();
			if (object.has(MESSAGE)) {
				if (response.getResponseCode() == HttpsURLConnection.HTTP_BAD_REQUEST)
					m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_RESULT)));
				else
					m_progress.setStatus(new Message(Message.ERROR, object.getString(MESSAGE)));
			}
			return null;
		}
	}

	// post request to create the report for selected issues (non compliant), it
	// will return the report id
	private String createNonCompliantIssuesReport(String scanId, String format) throws IOException, JSONException {
		IAuthenticationProvider authProvider = m_scanProvider.getAuthenticationProvider();
		if (authProvider.isTokenExpired()) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_LOGIN_EXPIRED)));
			return null;
		}

		String request_url = authProvider.getServer() + String.format(API_REPORT_SELECTED_ISSUES, SCOPE, scanId);
		Map<String, String> request_headers = authProvider.getAuthorizationHeader(true);
		request_headers.put("Content-Type", "application/json; charset=UTF-8");
		request_headers.put("Accept", "application/json");

		HttpClient client = new HttpClient(m_scanProvider.getAuthenticationProvider().getProxy());
		HttpResponse response = client.post(request_url, request_headers, getBodyParams(format).toString());
		if (response.getResponseCode() != HttpsURLConnection.HTTP_OK) {
			return null;
		}

		JSONObject obj = (JSONObject) response.getResponseBodyAsJSON();
		String reportId = obj.getString("Id");
		return reportId;
	}

	private JSONObject getBodyParams(String format) throws JSONException, UnsupportedEncodingException {
		JSONObject body = new JSONObject();
		body.put("Configuration", getConfiguration(format));
		body.put("ApplyPolicies", "All");
		return body;
	}

	private JSONObject getConfiguration(String format) throws JSONException {
		JSONObject configParams = new JSONObject();
		configParams.put("Summary", true);
		configParams.put("Details", true);
		configParams.put("Discussion", false);
		configParams.put("Overview", true);
		configParams.put("TableOfContent", true);
		configParams.put("Advisories", true);
		configParams.put("FixRecommendation", true);
		configParams.put("History", true);
		configParams.put("IsTrialReport", false);
		configParams.put("ReportFileType", format);
		configParams.put("Title", getScanName());
		configParams.put("Notes", "");
		configParams.put("Locale", SystemUtil.getLocale());
		return configParams;
	}

	private String getScanName() {
		JSONObject obj;
		try {
			obj = m_scanProvider.getScanDetails(m_scanId);
			return obj.getString("Name");
		} catch (IOException | JSONException e) {
			m_progress.setStatus(new Message(Message.ERROR, Messages.getMessage(ERROR_GETTING_DETAILS, e.getMessage())),
					e);
			return "";
		}

	}
}
