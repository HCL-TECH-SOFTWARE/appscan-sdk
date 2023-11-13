/**
 * © Copyright HCL Technologies Ltd. 2023.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sca;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.auth.IAuthenticationProvider;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.CloudScanServiceProvider;
import com.hcl.appscan.sdk.scan.IScan;
import com.hcl.appscan.sdk.scan.IScanFactory;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;

import java.util.Map;

public class SCAScanFactory implements IScanFactory {

    @Override
    public IScan create(Map<String, String> properties, IProgress progress, IAuthenticationProvider authProvider) {
        IScanServiceProvider serviceProvider = new CloudScanServiceProvider(progress, authProvider);
        return new SCAScan(properties, progress, serviceProvider);
    }

    @Override
    public String getType() {
        return CoreConstants.SOFTWARE_COMPOSITION_ANALYZER;
    }
}
