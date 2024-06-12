/**
 * © Copyright HCL Technologies Ltd. 2023, 2024.
 * LICENSE: Apache License, Version 2.0 https://www.apache.org/licenses/LICENSE-2.0
 */

package com.hcl.appscan.sdk.scanners.sca;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.sast.SASTConstants;
import com.hcl.appscan.sdk.scanners.sast.SASTScan;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public class SCAScan extends SASTScan implements SASTConstants {
    private static final long serialVersionUID = 1L;
    private static final String REPORT_FORMAT = "html"; //$NON-NLS-1$

    public SCAScan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
        super(properties, progress, provider);
    }

    @Override
    public void run() throws ScannerException, InvalidTargetException {
        String target = getTarget();

        if(target == null || !(new File(target).exists()))
            throw new InvalidTargetException(Messages.getMessage(TARGET_INVALID, target));

        try {
            if(getProperties().containsKey(CoreConstants.INCLUDE_SCA) && getProperties().containsKey("ApplicationFileId")) {
                submitScan();
            } else {
                generateIR();
                analyzeIR();
            }
        } catch(IOException e) {
            throw new ScannerException(Messages.getMessage(SCAN_FAILED, e.getLocalizedMessage()));
        }
    }

    @Override
    public String getType() {
        return CoreConstants.SOFTWARE_COMPOSITION_ANALYZER;
    }

    @Override
    protected void submitScan() {
        setScanId(getServiceProvider().createAndExecuteScan(CoreConstants.SCA, getProperties()));
    }
}
