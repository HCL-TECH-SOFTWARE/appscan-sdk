/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.dynamic;

import java.io.File;
import java.io.IOException;
import java.util.Map;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.DefaultProgress;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scan.CloudScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ASoCScan;
import com.hcl.appscan.sdk.utils.ServiceUtil;
import org.apache.wink.json4j.JSONException;
import org.apache.wink.json4j.JSONObject;

public class DASTScan extends ASoCScan implements DASTConstants {

	private static final long serialVersionUID = 1L;
	private static final String REPORT_FORMAT = "html"; //$NON-NLS-1$
	
	public DASTScan(Map<String, String> properties, IScanServiceProvider provider) {
		super(properties, new DefaultProgress(), provider);
	}
	
	public DASTScan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
		super(properties, progress, provider);
	}

	@Override
	public void run() throws ScannerException, InvalidTargetException {
		String type = DYNAMIC_ANALYZER;
		String target = getTarget();
		
		if(target == null)
			throw new InvalidTargetException(Messages.getMessage(TARGET_INVALID, target));

		Map<String, String> params = getProperties();
		params.put(STARTING_URL, target);

		IAuthenticationProvider authProvider = getServiceProvider().getAuthenticationProvider();
		if(!params.containsKey(PRESENCE_ID) && !ServiceUtil.isValidUrl(target, authProvider, authProvider.getProxy())) {
            if(authProvider.isAppScan360()) {
                throw new ScannerException("Either you don't have DAST subscription or the starting URL is invalid:"+ target);
            }
			throw new ScannerException(Messages.getMessage(CoreConstants.ERROR_URL_VALIDATION, target));
		}

		String scanLoginType = null;
		if (params.get(LOGIN_TYPE) != null) {
			scanLoginType = params.get(LOGIN_TYPE);
		}

		if (("Manual").equals(scanLoginType)) {
			String trafficFile = params.remove(TRAFFIC_FILE);
			if (trafficFile != null && new File(trafficFile).isFile()) {
				File fileTraffic = new File(trafficFile);

				try {
					String fileTrafficId = getServiceProvider().submitFile(fileTraffic);
					if (fileTrafficId == null) {
						throw new ScannerException(Messages.getMessage(ERROR_FILE_UPLOAD, fileTraffic.getName()));
					}
					params.put(TRAFFIC_FILE_ID, fileTrafficId);
				} catch (IOException e) {
					throw new ScannerException(Messages.getMessage(SCAN_FAILED, e.getLocalizedMessage()));
				}
			} else if(trafficFile != null){
				throw new ScannerException(Messages.getMessage(ERROR_FILE_UPLOAD,trafficFile));
			}
		}

		String scanFile = params.remove(SCAN_FILE);

		if (scanFile != null && new File(scanFile).isFile()) {
			File file = new File(scanFile);

			try {
				String fileId = getServiceProvider().submitFile(file);
				if(fileId == null)
					throw new ScannerException(Messages.getMessage(ERROR_FILE_UPLOAD, file.getName()));
				params.put(SCAN_FILE_ID, fileId);
			} catch (IOException e) {
				throw new ScannerException(Messages.getMessage(SCAN_FAILED, e.getLocalizedMessage()));
			}
		}

        try {
            JSONObject propertiesJSON = createJSONForProperties(params);
            setScanId(getServiceProvider().createAndExecuteScan(type, propertiesJSON));
        } catch (JSONException e) {
            throw new ScannerException(Messages.getMessage(ERROR_RUNNING_SCAN, e.getLocalizedMessage()));
        }

		if(getScanId() == null)
			throw new ScannerException(Messages.getMessage(ERROR_CREATING_SCAN));
	}

    private JSONObject createJSONForProperties(Map<String, String> params) throws JSONException {
        JSONObject json = new JSONObject(params);
        if(!params.containsKey(SCAN_FILE_ID)) {
            return json.put(SCAN_CONFIGURATION, createScanConfiguration(json));
        } else {
            return json;
        }
    }

    private JSONObject createScanConfiguration(JSONObject json) throws JSONException {
        JSONObject scanConfiguration = new JSONObject();
        scanConfiguration.put(TARGET, createTarget(json));
        if ((AUTOMATIC).equals(json.get(LOGIN_TYPE))) {
            scanConfiguration.put(LOGIN, createLogin(json));
        }
        scanConfiguration.put(TESTS, createTests(json));
        return scanConfiguration;
    }

    private JSONObject createTarget(JSONObject json) throws JSONException {
        return new JSONObject().put(STARTING_URL, json.remove(STARTING_URL));
    }

    private JSONObject createLogin(JSONObject json) throws JSONException {
        JSONObject login = new JSONObject();
            if (json.containsKey(LOGIN_USER) && json.containsKey(LOGIN_PASSWORD)) {
                login.put(USER_NAME, json.remove(LOGIN_USER));
                login.put(PASSWORD, json.remove(LOGIN_PASSWORD));
            }
            if (json.containsKey(EXTRA_FIELD)) {
                login.put(EXTRA_FIELD, json.remove(EXTRA_FIELD));
            }
        return login;
    }

    private JSONObject createTests(JSONObject json) throws JSONException {
        return new JSONObject().put(TEST_OPTIMIZATION_LEVEL, json.remove(TEST_OPTIMIZATION_LEVEL));
    }

	@Override
	public String getType() {
		return DAST;
	}

	@Override
	public String getReportFormat() {
		return REPORT_FORMAT;
	}
}
