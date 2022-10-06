/**
 * © Copyright HCL Technologies Ltd. 2018, 2022.
 */
package com.hcl.appscan.sdk.results;

import java.io.IOException;

import org.apache.wink.json4j.JSONArray;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.logging.Message;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.utils.SystemUtil;

public class NonCompliantIssuesResultProvider extends CloudResultsProvider {
	private static final long serialVersionUID = 1L;

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
	protected JSONObject getReportParams(String format) throws JSONException {
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
		
		JSONObject params = new JSONObject();
		params.put("Configuration", configParams);
		params.put("ApplyPolicies", "All");
		return params;
	}
}
