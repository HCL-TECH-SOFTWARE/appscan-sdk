/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2022.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.dynamic;

import java.io.File;
import java.io.IOException;
import java.util.Map;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.DefaultProgress;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ASoCScan;
import com.hcl.appscan.sdk.utils.ServiceUtil;

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

        	if(!ServiceUtil.isValidUrl(params.get(STARTING_URL),getServiceProvider().getAuthenticationProvider())) {
            		throw new ScannerException(Messages.getMessage(CoreConstants.ERROR_URL_VALIDATION));
        	}

		String scanLoginType = null;
		if (params.get(LOGIN_TYPE) != null) {
			scanLoginType = params.get(LOGIN_TYPE);
			params.remove(LOGIN_TYPE);
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
			type = DYNAMIC_ANALYZER_WITH_FILE;
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

		setScanId(getServiceProvider().createAndExecuteScan(type, params));

		if(getScanId() == null)
			throw new ScannerException(Messages.getMessage(ERROR_CREATING_SCAN));
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
