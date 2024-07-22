/**
 * © Copyright IBM Corporation 2016.
 * © Copyright HCL Technologies Ltd. 2017, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sast;

import java.util.Map;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.CloudScanServiceProvider;
import com.hcl.appscan.sdk.scan.IScan;
import com.hcl.appscan.sdk.scan.IScanFactory;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;

public class SASTScanFactory implements IScanFactory, SASTConstants {

	@Override
	public IScan create(Map<String, String> properties, IProgress progress, IAuthenticationProvider authProvider) {
		IScanServiceProvider serviceProvider = new CloudScanServiceProvider(progress, authProvider);
		if(properties.containsKey(CoreConstants.INCLUDE_SCA)) {
                    return new SAST_SCA_Scan(properties, progress, serviceProvider);
		}
		return new SASTScan(properties, progress, serviceProvider);
	}

	@Override
	public String getType() {
		return SAST;
	}
}
