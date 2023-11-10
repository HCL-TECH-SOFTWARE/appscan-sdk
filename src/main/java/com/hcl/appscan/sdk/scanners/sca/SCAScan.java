package com.hcl.appscan.sdk.scanners.sca;

import com.hcl.appscan.sdk.CoreConstants;
import com.hcl.appscan.sdk.Messages;
import com.hcl.appscan.sdk.error.InvalidTargetException;
import com.hcl.appscan.sdk.error.ScannerException;
import com.hcl.appscan.sdk.logging.IProgress;
import com.hcl.appscan.sdk.scan.IScanServiceProvider;
import com.hcl.appscan.sdk.scanners.ASoCScan;
import com.hcl.appscan.sdk.scanners.sast.SAClient;
import com.hcl.appscan.sdk.scanners.sast.SASTConstants;
import com.hcl.appscan.sdk.scanners.sast.SASTScan;

import java.io.File;
import java.io.IOException;
import java.net.Proxy;
import java.util.Map;

public class SCAScan extends SASTScan implements SASTConstants {
    private static final long serialVersionUID = 1L;
    private static final String REPORT_FORMAT = "html"; //$NON-NLS-1$
    private File m_irx;

    public SCAScan(Map<String, String> properties, IProgress progress, IScanServiceProvider provider) {
        super(properties, progress, provider);
    }

    @Override
    public void run() throws ScannerException, InvalidTargetException {
        String target = getTarget();

        if(target == null || !(new File(target).exists()))
            throw new InvalidTargetException(Messages.getMessage(TARGET_INVALID, target));

        try {
            generateIR();
            analyzeIR();
        } catch(IOException e) {
            throw new ScannerException(Messages.getMessage(SCAN_FAILED, e.getLocalizedMessage()));
        }
    }

    @Override
    public String getType() {
        return CoreConstants.SOFTWARE_COMPOSITION_ANALYZER;
    }

    private void analyzeIR() throws IOException, ScannerException {
        if(getProperties().containsKey(PREPARE_ONLY))
            return;

        String fileId = getServiceProvider().submitFile(m_irx);
        if(fileId == null)
            throw new ScannerException(Messages.getMessage(ERROR_FILE_UPLOAD, m_irx.getName()));

        Map<String, String> params = getProperties();
        params.put(FILE_ID, fileId);
        setScanId(getServiceProvider().createAndExecuteScan(CoreConstants.SCA, params));
        if(getScanId() == null)
            throw new ScannerException(Messages.getMessage(ERROR_SUBMITTING_IRX));
    }
}
